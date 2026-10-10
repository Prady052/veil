// The W3C VC 2.0 envelope for a Veil credential.
// Shared by the issuer (builds it) and the wallet/verifiers (read it back).

const PROOF_TYPE = "VeilEdDSAPoseidon2026"; // custom proof type, not a standard cryptosuite
const ID_PREFIX = "urn:veil:credential:";

// Build the credential WITHOUT its proof. The issuer adds the proof after signing.
function buildUnsignedVc({ did, credentialId, holderCommitment, subject, validFrom, validUntil }) {
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: ID_PREFIX + credentialId,
        type: ["VerifiableCredential", "VeilIdentityCredential"],
        issuer: did,
        validFrom,
        validUntil,
        credentialSubject: {
            holderCommitment,
            name: subject.name,
            dateOfBirth: subject.dateOfBirth,
            state: subject.state,
            incomeBand: subject.incomeBand,
            employmentStatus: subject.employmentStatus,
        },
    };
}

// Read a VC back into the flat claims object that encodeAttributes() expects.
// Both the issuer and anyone checking the VC use this, so they always agree.
function claimsFromVc(vc) {
    if (!vc.id || !vc.id.startsWith(ID_PREFIX)) throw new Error("Not a Veil credential id");
    const s = vc.credentialSubject;
    return {
        credentialId: vc.id.slice(ID_PREFIX.length),
        holderCommitment: s.holderCommitment,
        name: s.name,
        dateOfBirth: s.dateOfBirth,
        state: s.state,
        incomeBand: s.incomeBand,
        employmentStatus: s.employmentStatus,
        issuedAt: vc.validFrom.slice(0, 10),   // "2026-10-10T09:30:00Z" -> "2026-10-10"
        expiresAt: vc.validUntil.slice(0, 10),
    };
}

module.exports = { PROOF_TYPE, buildUnsignedVc, claimsFromVc };
