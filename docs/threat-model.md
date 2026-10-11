# Veil Threat Model (v0)

Status as of 11 Oct 2026, end of Week 3. For each attack I say whether the defence is built or still planned. See [design.md](design.md) for the protocol.

## 1. What I'm protecting

| Goal | Meaning |
| --- | --- |
| **Soundness** | A holder can't prove something false about themselves |
| **Privacy** | A verifier learns only that the requested predicates hold |
| **Unlinkability** | Verifiers, even working together, can't tell that two presentations came from the same person |
| **No tracking by the issuer** | The issuer doesn't learn where a credential is used |

## 2. Adversaries

### 2.1 Malicious holder

Wants to prove something that isn't true.

| Attack | Defence | Status |
| --- | --- | --- |
| Edit an attribute in the credential | The circuit checks the issuer's signature over `Poseidon(attrs)`. Any change breaks it | Built, tested |
| Reorder the attributes | Poseidon is order-sensitive, so the hash changes | Built, tested |
| Sign their own credential with their own key | The verifier takes the issuer key from the trusted issuer's DID document, never from the holder | Built, tested |
| Prove an easier statement than the one requested, or switch a predicate off (operator 0) | The verifier builds the public inputs from its own request. A proof made for other inputs fails | Built, tested |
| Point a predicate at a slot that doesn't exist, which would read as 0 | The circuit requires the slot number to match exactly one real slot | Built, tested |
| Use field wrap-around to pass a comparison | For `>=` and `<=` both sides must fit in 32 bits | Built, tested |
| Use someone else's credential file | Holder binding: the circuit must check `Poseidon(holderSecret) == attrs[2]` | **Not built. Planned, Week 4.** Today a copied credential file can be used to make proofs |
| Use a revoked or expired credential | Non-membership proof against the issuer's revocation tree, and an expiry check | **Not built. Planned, Week 6** |

### 2.2 Colluding verifiers

Want to link one person across sites by comparing what they received.

| What they compare | Why it doesn't link | Status |
| --- | --- | --- |
| The proofs | Groth16 proofs are randomised. Two proofs from one credential for one request shared 0 of 8 numbers | Built, observed once. The 1,000-holder linkage experiment is planned for Week 7 |
| The public inputs | They hold only the issuer key and the verifier's own request, which are the same for every holder | Built |
| `verificationMethod` | It names the issuer's key and is the same for every holder of that key | Built |
| A pseudonym | It will be `Poseidon(holderSecret, verifierDomain)`: stable at one site, unrelated across sites | **Planned, Week 4** |

### 2.3 Network attacker

Captures a presentation and tries to reuse it.

| Attack | Defence | Status |
| --- | --- | --- |
| Replay a captured proof to the same or another verifier | The verifier's nonce and domain become public inputs | **Not built. Planned, Week 4.** Today a captured presentation can be replayed for the same request |
| Change the issuer's DID document in transit to swap in another key | `did:web` requires https. My code allows plain http only for `localhost` | Built |

### 2.4 Curious issuer

Wants to learn where a credential is used, or to act as the holder.

| Attack | Defence | Status |
| --- | --- | --- |
| Learn the holder secret, then impersonate the holder or compute their pseudonyms | The wallet sends only `Poseidon(holderSecret)`. The secret never leaves the device | Built |
| See each presentation | The holder never contacts the issuer when presenting | Built |
| Learn which credential a revocation check is about | The wallet will download the whole revocation tree, not ask for its own path | **Planned, Week 6** |

One thing the issuer does see: a verifier fetches `did.json` from the issuer's site. That shows the issuer that a verifier is active, not which holder is presenting. A verifier can cache the document to reduce it.

## 3. Assumptions

- The holder's device and the holder secret are not compromised.
- The issuer is honest about the data it signs. A proof shows that the issuer signed a claim, not that the claim is true. In this project the issuer signs mock data with no identity check.
- The issuer's private key stays secret.
- Poseidon, EdDSA on BabyJubJub and Groth16 are secure as commonly assumed.
- The circuit has no under-constrained signals. My tests don't establish this on their own (see limit 7).

## 4. Known limits

1. **Trust in the issuer's domain.** With `did:web`, whoever controls the issuer's domain, DNS or web server controls the issuer's key.
2. **Key compromise.** It's handled only by rotating the key in the DID document. Credentials signed by the compromised key stay valid until the key is removed, and then every credential under that key fails at once.
3. **Single-party trusted setup.** I ran the Groth16 setup alone. Whoever keeps the setup randomness could forge proofs. This is fine for a demo and not for production.
4. **Small anonymity set.** A holder is hidden among the valid credentials of that issuer. An issuer with few holders gives weak anonymity.
5. **Predicates can leak.** A request for `dateOfBirth == 1995-03-14`, or a very narrow range, identifies the person and links them across sites without breaking any cryptography. The defence is policy in the wallet and the verifier, planned for Week 5.
6. **Side channels.** IP addresses, cookies, timing and proof-generation time are out of scope.
7. **Test coverage.** The 21 circuit tests use the honest witness generator. They can't catch a signal that is assigned and never constrained. I plan to run `circomspect` for that.
8. **Losing the device.** The holder secret is lost with it, and the credential becomes unusable. The holder needs a new credential bound to a new secret.
9. **Custom proof type.** Veil's proof type is not a standardised Data Integrity cryptosuite, so standard VC tools can't verify these credentials.
