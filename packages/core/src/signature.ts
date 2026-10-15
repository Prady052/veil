// Checking an issuer's EdDSA-Poseidon signature on BabyJubJub, in Node or in the browser.
// The issuer signs with circomlibjs; this checks with @zk-kit/eddsa-poseidon, which runs in a
// browser. Both test the same equation:
//     S * B8 == R8 + 8 * Poseidon(R8x, R8y, Ax, Ay, M) * A
// and packages/core/test/signature.test.ts checks that they agree.
import { verifySignature } from "@zk-kit/eddsa-poseidon";
import type { PublicKey } from "./did";
import type { EddsaSignature } from "./vc";

export function verifyIssuerSignature(message: bigint, signature: EddsaSignature, key: PublicKey): boolean {
    try {
        return verifySignature(
            message,
            { R8: [BigInt(signature.R8x), BigInt(signature.R8y)], S: BigInt(signature.S) },
            [BigInt(key.x), BigInt(key.y)],
        );
    } catch {
        return false; // malformed numbers are simply an invalid signature
    }
}
