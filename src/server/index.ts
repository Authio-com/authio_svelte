import { JwtVerifier, type Session } from "@useauthio/node";

export interface VerifyOptions {
  apiUrl?: string;
  issuer?: string;
  audience?: string;
}

const RESERVED_JWT_CLAIMS = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "jti",
  "nbf",
  "scope",
  "scopes",
  "sid",
  "act_org",
  "act_role",
  "client_id",
  "token_type",
  "project_id",
  "is_impersonation",
  "impersonator_user_id",
  "impersonator_email",
  "imp_grant_id",
  "flags",
]);

const verifierCache = new Map<string, JwtVerifier>();

function getVerifier(opts: VerifyOptions): JwtVerifier {
  const apiUrl = (opts.apiUrl ?? "https://api.authio.com").replace(/\/$/, "");
  const issuer = opts.issuer ?? apiUrl;
  const audience = opts.audience ?? "authio";
  const key = `${apiUrl}|${issuer}|${audience}`;
  let v = verifierCache.get(key);
  if (!v) {
    v = new JwtVerifier(apiUrl, issuer, audience);
    verifierCache.set(key, v);
  }
  return v;
}

/**
 * A verified Authio session as exposed by the Svelte SDK. Mirrors
 * `@useauthio/node`'s `Session` with the addition of merged custom claims.
 */
export interface AuthioServerSession extends Session<Record<string, unknown>> {
  /** T2.4 custom claims merged into the access token. */
  claims: Record<string, unknown>;
  isImpersonation?: boolean;
  impersonatorEmail?: string;
}

/**
 * Verify an Authio access token from a cookie or Authorization header.
 *
 * Returns the typed `AuthioServerSession`, or `null` when the token is
 * missing / expired / cryptographically invalid. Caches the JWKS
 * internally — safe to call on every request.
 */
export async function verifySessionCookie(
  token: string | null | undefined,
  opts: VerifyOptions = {},
): Promise<AuthioServerSession | null> {
  if (!token) return null;
  const verifier = getVerifier(opts);
  try {
    const claims = await verifier.verify(token);
    const merged: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(claims)) {
      if (RESERVED_JWT_CLAIMS.has(k)) continue;
      merged[k] = v;
    }
    return {
      sessionId: claims.sid ?? "",
      userId: claims.sub,
      orgId: claims.act_org ? claims.act_org : null,
      role: claims.act_role ? claims.act_role : null,
      expiresAt: claims.exp
        ? new Date(claims.exp * 1000).toISOString()
        : new Date().toISOString(),
      claims: merged,
      flags: Array.isArray(claims.flags) ? claims.flags : [],
      isImpersonation:
        claims.is_impersonation === true ? true : undefined,
      impersonatorEmail:
        typeof claims.impersonator_email === "string"
          ? claims.impersonator_email
          : undefined,
    };
  } catch {
    return null;
  }
}

export type { Session } from "@useauthio/node";
