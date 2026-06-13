import { writable, type Writable } from "svelte/store";
import type { Session } from "@useauthio/node";

export type { Session } from "@useauthio/node";

export interface AuthioState {
  isLoaded: boolean;
  session: Session | null;
}

const INITIAL: AuthioState = { isLoaded: false, session: null };

export function createAuthioStore(initial?: Session | null): Writable<AuthioState> {
  return writable<AuthioState>({
    isLoaded: initial !== undefined,
    session: initial ?? null,
  });
}

export const authio = writable<AuthioState>(INITIAL);

export function setSession(session: Session | null): void {
  authio.set({ isLoaded: true, session });
}

export function clearSession(): void {
  authio.set({ isLoaded: true, session: null });
}

export interface SignInOptions {
  email: string;
  apiUrl?: string;
  publishableKey: string;
  redirectUrl: string;
}

/**
 * Browser-side helper: kicks off the Authio magic-link flow.
 * Returns when auth-core has accepted the request; the user receives an
 * email whose link routes back through your `redirectUrl`.
 */
export async function signIn(opts: SignInOptions): Promise<void> {
  const apiUrl = (opts.apiUrl ?? "https://api.authio.com").replace(/\/$/, "");
  const res = await fetch(`${apiUrl}/v1/auth/magic-link/start`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-publishable-key": opts.publishableKey,
    },
    body: JSON.stringify({
      email: opts.email,
      redirect_url: opts.redirectUrl,
    }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { message?: string };
    throw new Error(err.message ?? `auth-core returned ${res.status}`);
  }
}
