import type { Check } from "@veil/core";

// The list of credential checks, ticked or crossed
export function Checks({ checks }: { checks: Check[] }) {
    return (
        <ul className="checks">
            {checks.map((c) => (
                <li key={c.name} className={c.ok ? "ok" : "bad"}>
                    {c.ok ? "✔" : "✘"} {c.name}
                    {c.detail && <span className="muted"> ({c.detail})</span>}
                </li>
            ))}
        </ul>
    );
}
