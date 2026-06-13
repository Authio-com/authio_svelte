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
  /** Email address (or E.164 phone) to send the magic-link to. */
  email: string;
  /** auth-core base URL. Defaults to the canonical identity origin. */
  apiUrl?: string;
  /**
   * Project ID (`proj_…`). Sent as the `X-Authio-Project` header — the
   * canonical project resolver for auth-core (NOT `x-publishable-key`).
   * Aligned with `@useauthio/react` / `@useauthio/vue`.
   */
  projectId: string;
  /**
   * URL the magic-link click-through lands on. Sent as `redirect_uri`.
   * Aligned with `@useauthio/react` / `@useauthio/vue`.
   */
  redirectUri: string;
}

/**
 * Browser-side helper: kicks off the Authio magic-link flow.
 * Returns when auth-core has accepted the request; the user receives an
 * email whose link routes back through your `redirectUri`.
 *
 * Wire contract (auth-core magiclink.go): `POST /v1/auth/magic-link/send`,
 * header `X-Authio-Project`, body `{ destination, redirect_uri }`.
 */
export async function signIn(opts: SignInOptions): Promise<void> {
  const apiUrl = (opts.apiUrl ?? "https://identity.authio.com").replace(/\/$/, "");
  const res = await fetch(`${apiUrl}/v1/auth/magic-link/send`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Authio-Project": opts.projectId,
    },
    body: JSON.stringify({
      destination: opts.email,
      redirect_uri: opts.redirectUri,
    }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { message?: string };
    throw new Error(err.message ?? `auth-core returned ${res.status}`);
  }
}
