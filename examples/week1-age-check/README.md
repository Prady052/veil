# Week 1: a toy age check

This is where Veil started. It is not part of the system any more; I keep it because it shows the core idea at its smallest, one step at a time.

| File | What it shows |
| --- | --- |
| `playground.js` | Poseidon hashing and EdDSA on BabyJubJub in plain JavaScript: sign a credential hash, then watch the signature fail when one attribute changes |
| `age_simple.circom` | The smallest useful circuit: prove `dob <= today - 180000` without revealing `dob`. It has no signature, so anyone can type any date of birth |
| `age_check.circom` | The same check, plus the issuer's EdDSA signature over `Poseidon(dob)`, verified inside the circuit |
| `issue_age.js` | Plays the issuer: signs a date of birth and writes a circuit input file |
| `verify_age.js` | Plays the verifier: builds the public inputs itself from a trusted issuer key, instead of trusting the prover's `public.json` |
| `inputs/` | Sample inputs: an adult, a minor, and a "forged" credential whose date of birth was edited after signing |

What it taught me, and where each idea ended up in the real circuit (`circuits/presentation.circom`):

- Comparators are only sound on inputs that fit in their bit width, so every compared value needs a `Num2Bits` range check. Used in `circuits/lib/predicate.circom`.
- A circuit that doesn't check where a value came from proves nothing useful. The signature check became `circuits/lib/credential.circom`.
- A verifier that reads the issuer key from the proof's own public inputs accepts a credential the holder signed with their own key. The verifier must build the public inputs itself. Every verifier in Veil does this.

## Running it

Run these from the repository root. They write their outputs to `build/`, which is not committed.

```bash
node examples/week1-age-check/playground.js
```

```bash
circom examples/week1-age-check/age_check.circom --r1cs --wasm --sym -o build -l node_modules
```

```bash
node build/age_check_js/generate_witness.js build/age_check_js/age_check.wasm examples/week1-age-check/inputs/age_check_minor.json build/age_check_minor.wtns
```

The last command fails with `Assert Failed`: no witness exists for a minor, so no proof can be made. Swap in `age_check_ok.json` and it succeeds; swap in `age_check_forged.json` and the signature check fails.

For a full prove-and-verify run, first issue a fresh credential with `issue_age.js`, so that `verify_age.js` checks it against the same issuer key, then run the Groth16 setup, prove and verify steps from the snarkjs documentation with the `pot14` Phase 1 file in `build/`.
