// Turning a request's predicates into plain words, so the holder knows what they are agreeing to.
import type { Predicate } from "@veil/core";

const LABELS: Record<string, string> = {
    name: "name",
    dateOfBirth: "date of birth",
    state: "state",
    incomeBand: "income band",
    employmentStatus: "employment status",
    issuedAt: "issue date",
    expiresAt: "expiry date",
};

const DATES = new Set(["dateOfBirth", "issuedAt", "expiresAt"]);

export function describePredicate(p: Predicate): string {
    const label = LABELS[p.attr] ?? p.attr;
    const value = Array.isArray(p.value) ? p.value.join(", ") : p.value;
    const date = DATES.has(p.attr);
    switch (p.op) {
        case "==":
            return `Your ${label} is ${value}`;
        case ">=":
            return date ? `Your ${label} is on or after ${value}` : `Your ${label} is at least ${value}`;
        case "<=":
            return date ? `Your ${label} is on or before ${value}` : `Your ${label} is at most ${value}`;
        case "in":
            return `Your ${label} is one of: ${value}`;
        default:
            return `${label} ${p.op} ${value}`;
    }
}

// An "==" predicate reveals the value itself, not just a fact about it
export function revealsValue(p: Predicate): boolean {
    return p.op === "==" || (p.op === "in" && Array.isArray(p.value) && p.value.length === 1);
}
