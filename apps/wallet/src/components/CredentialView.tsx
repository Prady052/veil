import type { VerifiableCredential } from "@veil/core";

// The stored credential, as the holder sees it. Only the holder ever sees these values:
// a verifier gets a proof about them, never the values themselves.
export function CredentialView({ vc }: { vc: VerifiableCredential }) {
    const s = vc.credentialSubject;
    const rows: [string, string][] = [
        ["Name", s.name],
        ["Date of birth", s.dateOfBirth],
        ["State", s.state],
        ["Income band", s.incomeBand],
        ["Employment", s.employmentStatus],
        ["Issuer", vc.issuer],
        ["Valid until", vc.validUntil.slice(0, 10)],
    ];
    return (
        <table className="claims">
            <tbody>
                {rows.map(([label, value]) => (
                    <tr key={label}>
                        <th>{label}</th>
                        <td>{value}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}
