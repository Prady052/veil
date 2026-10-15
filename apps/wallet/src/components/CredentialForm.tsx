import { useState, type FormEvent } from "react";
import { EMPLOYMENT, INCOME_BANDS, STATES, type Subject } from "@veil/core";

interface Props {
    busy: boolean;
    onSubmit: (subject: Subject) => void;
}

// The claims the holder asks the issuer to certify. The issuer signs whatever it is
// sent (mock data): a real issuer would check the person's identity first.
export function CredentialForm({ busy, onSubmit }: Props) {
    const [subject, setSubject] = useState<Subject>({
        name: "Sameer Patil",
        dateOfBirth: "1995-03-14",
        state: "MH",
        incomeBand: "5L-8L",
        employmentStatus: "employed",
    });

    // Update one field, keep the rest
    const change = (field: keyof Subject) => (value: string) => setSubject({ ...subject, [field]: value });

    function submit(e: FormEvent) {
        e.preventDefault(); // stop the browser's own form submission, which would reload the page
        onSubmit(subject);
    }

    return (
        <form onSubmit={submit} className="form">
            <label>
                Name
                <input value={subject.name} onChange={(e) => change("name")(e.target.value)} required />
            </label>
            <label>
                Date of birth
                <input type="date" value={subject.dateOfBirth} onChange={(e) => change("dateOfBirth")(e.target.value)} required />
            </label>
            <label>
                State
                <select value={subject.state} onChange={(e) => change("state")(e.target.value)}>
                    {STATES.map((s) => <option key={s}>{s}</option>)}
                </select>
            </label>
            <label>
                Income band (per year)
                <select value={subject.incomeBand} onChange={(e) => change("incomeBand")(e.target.value)}>
                    {INCOME_BANDS.map((b) => <option key={b}>{b}</option>)}
                </select>
            </label>
            <label>
                Employment
                <select value={subject.employmentStatus} onChange={(e) => change("employmentStatus")(e.target.value)}>
                    {EMPLOYMENT.map((x) => <option key={x}>{x}</option>)}
                </select>
            </label>
            <button type="submit" disabled={busy}>{busy ? "Asking the issuer…" : "Get a credential"}</button>
        </form>
    );
}
