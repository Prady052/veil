# Veil Attribute Encoding (v1)

This is how I turn a credential's claims into the numbers that the issuer signs and the circuit checks. The issuer, the wallet and every circuit must follow this exactly. If a value is encoded differently anywhere, the signature won't verify.

## 1. Why I need an encoding

Circom circuits only work with **field elements**: whole numbers modulo the BN254 prime

```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617   (~2^254)
```

There is no text, no negative numbers and no native `<`. So every claim (name, state, income and so on) has to become a number below `p`, chosen so that the predicates I care about still work on that number.

All 10 numbers are hashed together with Poseidon, and the issuer signs that one hash with EdDSA on BabyJubJub:

```
M = Poseidon(attr[0], attr[1], ..., attr[9])
signature = EdDSA-Poseidon(issuerPrivKey, M)
```

## 2. Attribute vector layout

The slot order is fixed. Poseidon is order-sensitive (`Poseidon(1,2) ≠ Poseidon(2,1)`), so swapping two slots breaks every signature.

| Slot | Attribute | Encoding | Example value | Predicates supported |
|------|-----------|----------|---------------|----------------------|
| 0 | schemaVersion | Small integer | `1` | — |
| 1 | credentialId | Random 128-bit integer | `0x9f3c…` | Revocation (week 6) |
| 2 | holderCommitment | `Poseidon(holderSecret)`, where the secret is 31 random bytes | field element | Holder binding (week 4) |
| 3 | name | `Poseidon(byteLength, chunk1, chunk2, …)`, with UTF-8 bytes packed 31 per chunk | field element | Equality / disclose |
| 4 | dateOfBirth | `YYYYMMDD` integer | `19950314` | ≥, ≤, range |
| 5 | state | Enum index (see §3) | `1` (MH) | Equality, set membership |
| 6 | incomeBand | Ordinal enum index, **low → high** | `3` (5L–8L) | ≥, ≤, range |
| 7 | employmentStatus | Enum index | `1` (employed) | Equality, set membership |
| 8 | issuedAt | `YYYYMMDD` | `20261007` | — |
| 9 | expiresAt | `YYYYMMDD` | `20311007` | Expiry check (week 6) |

## 3. Enum lists

Value = position in the list + 1.

**States** (ISO 3166-2:IN codes)

| Value | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| State | MH | KA | DL | TN | GJ | UP | WB | RJ | KL | TG |

**Income bands**, ordered **low → high** (annual income, ₹)

| Value | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Band | < 2.5L | 2.5L – 5L | 5L – 8L | 8L – 12L | 12L + |

**Employment status**

| Value | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Status | employed | self-employed | student | unemployed | retired |

## 4. Rules

- **`0` means "attribute absent".** That's why enums start at 1, so a missing value can never be mistaken for a real one.
- **Enum lists are append-only.** Reordering or deleting an entry would silently change the meaning of every credential already issued. New entries only go at the end, and any breaking change bumps `schemaVersion`.
- **Income bands must stay ordered low → high.** The direction itself doesn't matter (high → low would also work), but the order has to be steady. Then "income under X" is one comparison instead of a set-membership check. An alphabetical order would break this: "under 8L" would become `band ∈ {2, 3, 5}`.
- **Dates and enums must be below 2^32.** Circom's comparators (`LessThan(n)` and the others) are only correct when both inputs fit in `n` bits. In the circuit I'll range-check these slots with `Num2Bits(32)` before comparing. Otherwise a cheating prover could pick a value that wraps around mod `p` and passes. `YYYYMMDD` values (about 2×10^7) and small enums fit easily.
- **Hash slots (2, 3) and the ID (1) are never compared with `<` or `>`.** They're only used for equality or as hash inputs, so they don't need the 32-bit bound.
- **Name chunks are 31 bytes, not 32.** A 32-byte chunk can be as large as 2^256 − 1, which is bigger than `p`. It would wrap around, and two different names could collide. 31 bytes (max ~2^248) is always below `p`. I also hash the byte length first so that `"Ab"` and `"Ab\0"` can't produce the same chunks.

## 5. How predicates map to comparisons

`T` is the verifier's date as `YYYYMMDD`, and it's a public input to the proof. Subtracting `N × 10000` takes `N` years off the year digits.

Rule of thumb: **"at least" includes the boundary, "under" excludes it.**

| Predicate | Comparison | Example (T = 20261007) |
|---|---|---|
| age ≥ 18 | `dob ≤ T − 180000` | `dob ≤ 20081007` |
| age < 25 | `dob > T − 250000` (i.e. `dob ≥ T − 250000 + 1`) | `dob > 20011007` |
| born after 1 Jan 2000 | `dob > 20000101` | — |
| income under ₹8 lakh | `incomeBand ≤ 3` | — |
| income at least ₹8 lakh | `incomeBand ≥ 4` | — |
| income ₹2.5L – ₹8L | `incomeBand ≥ 2 AND incomeBand ≤ 3` | — |
| lives in MH or KA | `state ∈ {1, 2}` | — |
| credential not expired | `T ≤ expiresAt` | — |

Boundary check for age < 25: someone born exactly on `20011007` turns 25 on T, so they must **fail**. That's why it's `>` and not `≥`.

## 6. Edge cases

**Born on 29 Feb 2008** (`dob = 20080229`). When does the age ≥ 18 check pass?

- On 28 Feb 2026: threshold = `20260228 − 180000 = 20080228`. Is `20080229 ≤ 20080228`? **No**, so not yet 18.
- On 1 Mar 2026: threshold = `20260301 − 180000 = 20080301`. Is `20080229 ≤ 20080301`? **Yes**, so 18.

In non-leap years, a person born on 29 Feb is treated as turning 18 on **1 March**. That matches the common legal convention, so I'm keeping it.

**Verifier date is 29 Feb** (e.g. T = `20280229`). The threshold `20280229 − 180000 = 20100229` isn't a real date, but that doesn't matter. It's only used as a number, and it still sits correctly between `20100228` and `20100301`, so the comparison gives the right answer.

**Leaks from predicates themselves.** The encoding can't stop a verifier from asking for something identifying. "`dob = 19950314`" or "`dob ≥ 19950314 AND dob ≤ 19950314`" reveals the exact birthday. Verifier request policies (week 5) should reject overly narrow predicates.
