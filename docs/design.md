# Veil Design (v0)

Last updated 12 Oct 2026, during Week 4 (holder binding and replay protection added). This describes what I've built so far and what's still planned. The threat model is in [threat-model.md](threat-model.md) and the attribute encoding is in [encoding.md](encoding.md).

## 1. What Veil does

A person holds one W3C Verifiable Credential and proves facts from it ("over 18", "lives in Maharashtra", "income under ₹8 lakh") to independent websites. A website learns that the fact is true and nothing else. Two websites can't tell that they dealt with the same person.

The problem statement comes from the ISEA Phase III Cryptography Hackathon 2026 (ISI Kolkata with Fortytwo Labs).

## 2. Roles

| Role | Does | Holds |
| --- | --- | --- |
| **Issuer** | Signs credentials. Publishes its public key in a `did:web` document | The issuer private key |
| **Holder** (wallet) | Stores the credential. Makes a zero-knowledge proof for each request | The credential and the holder secret |
| **Verifier** | Asks for predicates. Checks the proof | Nothing secret. It trusts one issuer DID |

The holder talks to verifiers directly. The issuer is not involved when a credential is presented.

## 3. The core idea

The issuer signs a hash that is cheap to check inside a circuit:

```
attrs = the 10 attributes, each encoded as a field element
M = Poseidon(attrs[0..9])
signature = EdDSA on BabyJubJub over M
```

One Circom circuit then checks the signature and the predicates together. The attributes and the signature are private inputs, so the verifier never sees them. I chose EdDSA on BabyJubJub with Poseidon because the signature check costs about 8,000 constraints. ECDSA or Ed25519 inside a circuit would cost far more.

## 4. Credential format

The credential is a W3C VC Data Model 2.0 JSON document. It carries the claims twice: readable in `credentialSubject`, and as 10 field elements in `proof.attributes`.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:veil:credential:<128-bit id>",
  "type": ["VerifiableCredential", "VeilIdentityCredential"],
  "issuer": "did:web:localhost%3A3000",
  "validFrom": "...", "validUntil": "...",
  "credentialSubject": { "holderCommitment": "...", "name": "...", "dateOfBirth": "...",
                         "state": "...", "incomeBand": "...", "employmentStatus": "..." },
  "proof": {
    "type": "VeilEdDSAPoseidon2026",
    "verificationMethod": "did:web:localhost%3A3000#key-1",
    "proofPurpose": "assertionMethod",
    "attributes": ["...10 field elements..."],
    "signature": { "R8x": "...", "R8y": "...", "S": "..." }
  }
}
```

**This is a custom proof type, not a standardised Data Integrity cryptosuite.** `VeilEdDSAPoseidon2026` and the JWK curve name `BabyJubJub` in the DID document are my own, not registered values. The standards-track alternative is the BBS cryptosuite, which I keep as a stretch comparison.

The signature covers only the 10 numbers. So anyone checking a credential must re-encode the readable claims and confirm they give the same numbers. That's why the encoding is a single shared module (`packages/core/encoding.js`).

## 5. Protocol

### 5.1 Issuance

1. The wallet creates a random `holderSecret` once and keeps it.
2. The wallet sends `holderCommitment = Poseidon(holderSecret)` and the claims to `POST /issue`.
3. The issuer validates the request, encodes the claims, computes `M` and signs it. Bad input (an unknown state, a date that doesn't exist) is rejected before anything is signed.
4. The wallet checks the credential it received:
   - the proof type is known;
   - the issuer's DID resolves, and the document is for that DID;
   - the signing key belongs to the issuer and is listed under `assertionMethod`;
   - the readable claims re-encode to the signed numbers;
   - the signature is valid;
   - the credential is inside its validity period.

The issuer never sees the holder secret. It signs mock data: real identity proofing is out of scope.

### 5.2 Presentation

1. The verifier sends a request: the issuer DID it trusts, its own domain, a fresh random nonce, and up to 4 predicates.

   ```json
   { "issuer": "did:web:localhost%3A3000",
     "domain": "agegate.example",
     "nonce": "<fresh 248-bit random number>",
     "predicates": [ { "attr": "dateOfBirth", "op": "<=", "value": "2008-10-11" } ] }
   ```
2. The holder makes a Groth16 proof and sends back only this:

   ```json
   { "verificationMethod": "did:web:localhost%3A3000#key-1", "proof": { "pi_a": [], "pi_b": [], "pi_c": [] } }
   ```
3. The verifier checks that the key belongs to the issuer it trusts, fetches that key from the issuer's DID document, and builds the public inputs **itself** from its own request. Then it verifies the proof.
4. The verifier records the nonce as used and refuses to accept it again.

The verifier never takes public inputs from the holder. This one rule stops four attacks: a self-made issuer key, a predicate quietly switched off, a proof made for a different request, and a proof replayed from an earlier request or another site.

The proof is bound to the request's domain, but that only helps if the holder made it for the site they are really talking to. A browser wallet must check that the request's domain matches that site, or a malicious site could relay another site's request. That check is planned for Week 5; the command-line scripts only print the domain.

## 6. The circuit

`circuits/presentation.circom` is `Presentation(10, 4)`: 10 attributes, 4 predicate slots.

| Inputs | Signals |
| --- | --- |
| Private (14) | `attrs[10]`, `R8x`, `R8y`, `S`, `holderSecret` |
| Public (16) | `Ax`, `Ay`, `nonce`, `domainHash`, `predAttr[4]`, `predOp[4]`, `predValue[4]` |

Rules:

1. **Credential** (`lib/credential.circom`): `M = Poseidon(attrs)`, and the signature on `M` is valid under `(Ax, Ay)`.
2. **Holder binding** (`lib/holder.circom`): `Poseidon(holderSecret)` equals `attrs[2]`, the holder commitment the issuer signed. A copied credential file is useless without the secret.
3. **Predicates** (`lib/predicate.circom`), for each of the 4 slots:
   - the slot number is a real slot, 0 to 9;
   - the operator is one of: 0 none, 1 `==`, 2 `>=`, 3 `<=`;
   - the chosen comparison is true.
4. **Request binding**: `nonce` and `domainHash` (the hash of the verifier's domain name) are public inputs. No other rule needs them, so each is used in one constraint of its own, to make sure it is tied to the proof whatever the proving tool does with unused inputs.

Disclosure of an attribute is the `==` predicate against a public value, so it needs no separate mechanism.

Comparators are only sound on 32-bit inputs. For `>=` and `<=` the circuit forces the attribute and the value to fit in 32 bits. For `==` that check is switched off, so hashed attributes (the name) can still be compared for equality.

Measured at the end of Week 3, before holder binding and request binding were added:

| Measure | Value |
| --- | --- |
| Constraints (total) | 10,326, of which about 205 per predicate |
| Proving time (Node, laptop) | 1.2 s |
| Proof size | 256 bytes (8 field elements) |
| Proving key | 5.4 MB |
| Witness generator (wasm) | 3.9 MB |

## 7. Testing

`npm test` runs 29 tests.

- **24 witness-level tests** ask whether an input can satisfy the circuit. 16 of them are negative tests that must produce no witness: forged credentials (4), stolen credentials (2), false predicates (4), malformed requests (4) and two boundary cases.
- **5 proof-level tests** make one real Groth16 proof and check it as a verifier would. Four are negative: a replay under a new nonce, a proof forwarded to another domain, a proof presented for different predicates, and a proof checked against another issuer's key. They need the keys from `npm run setup` and are skipped without them. I also broke the circuit on purpose three times to confirm the tests notice.

All of these use the honest witness generator, so they can't detect a signal that is assigned but never constrained. I plan to run `circomspect` for that.

## 8. What is built and what isn't

| Requirement | Status |
| --- | --- |
| Issue a VC signed by a key that resolves through `did:web` | Built |
| Prove predicates: `==`, `>=`, `<=` | Built |
| Disclose a subset of attributes | Built, as `==` |
| Set membership ("state is MH or KA") | **Not built yet** |
| Proofs to different verifiers share no linking value | Built: two proofs of the same statement had 0 of 8 numbers in common. The full linkage experiment is planned for Week 7 |
| Holder binding | Built: the circuit checks `Poseidon(holderSecret)` against the signed commitment |
| Nonce and domain binding (replay protection) | Built in the circuit and the verifier. The wallet-side domain check is planned for Week 5 |
| Per-verifier pseudonym | **Planned, Week 4** |
| Proving in the browser on a phone | **Planned, Week 4.** Proving currently runs in Node |
| Revocation and expiry | **Planned, Week 6** |
| Groth16 against PLONK | **Planned, Week 7** |

## 9. Trusted setup

Groth16 needs a trusted setup. Mine is single-party: I made the Powers of Tau file (2^14) and the circuit-specific key myself. That's fine for a demo and not for production, where Phase 1 would come from a public multi-party ceremony.
