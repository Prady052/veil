// What the wallet keeps on this device, in the browser's IndexedDB.
// IndexedDB is a small database every browser provides to each website. Unlike a page's
// variables, it survives reloads and restarts. Nothing here is ever sent anywhere.
import { createStore, del, get, set } from "idb-keyval";
import { randomField, type VerifiableCredential } from "@veil/core";

const store = createStore("veil-wallet", "wallet");
const SECRET_KEY = "holderSecret";
const CREDENTIAL_KEY = "credential";

// Remembered so that two calls at the same moment can't create two different secrets.
// (React runs start-up code twice in development to catch bugs, which would do exactly that.)
let secretPromise: Promise<string> | null = null;

// The holder secret is created ONCE, the first time the wallet opens, and reused forever
export function loadOrCreateSecret(): Promise<string> {
    secretPromise ??= (async () => {
        const existing = await get<string>(SECRET_KEY, store);
        if (existing) return existing;
        const secret = randomField().toString();
        await set(SECRET_KEY, secret, store);
        return secret;
    })();
    return secretPromise;
}

export function loadCredential(): Promise<VerifiableCredential | undefined> {
    return get<VerifiableCredential>(CREDENTIAL_KEY, store);
}

export function saveCredential(vc: VerifiableCredential): Promise<void> {
    return set(CREDENTIAL_KEY, vc, store);
}

// Deletes the credential AND the secret. Without the secret the credential could never be
// used again, so they go together.
export async function forgetWallet(): Promise<void> {
    await del(CREDENTIAL_KEY, store);
    await del(SECRET_KEY, store);
    secretPromise = null;
}
