import { JWTPayload } from 'jose';

/**
 * Authio access-token claim shape.
 *
 * Generic over `TClaims` so customers using the T2.4 custom-claims
 * feature get typed access to their own merged claims:
 *
 *   const claims = await verifier.verify<{
 *     stripe_customer_id: string;
 *     plan: "free" | "pro" | "enterprise";
 *   }>(token);
 *   claims.stripe_customer_id; // typed string
 *
 * For user tokens, `sub` is the user_id and `sid` carries the session
 * id. For M2M tokens (T2.1 client-credentials grant) `sub` is the
 * client_id, `token_type` is "m2m", and `scopes` carries the granted
 * scope set.
 */
type AuthioClaims<TClaims extends Record<string, unknown> = Record<string, never>> = JWTPayload & {
    sub: string;
    /** The active organization for this token. Empty string if the user has not yet selected an org. */
    act_org?: string;
    /** The active role within `act_org`. */
    act_role?: string;
    /** Session ID. Absent on M2M tokens. */
    sid?: string;
    /** "m2m" for client-credentials tokens; undefined / "user" otherwise. */
    token_type?: "user" | "m2m";
    /** Public client_id on M2M tokens (also stamped into `sub`). */
    client_id?: string;
    /** Project_id on M2M tokens. */
    project_id?: string;
    /** Array form of OAuth-2 scopes on M2M tokens. */
    scopes?: string[];
    /** Space-joined OAuth-2 scope claim on M2M tokens. */
    scope?: string;
    /** T3.4 — true when the session was minted by an Authio operator impersonating the user. */
    is_impersonation?: boolean;
    /** T3.4 — admin's user_id when is_impersonation is true. */
    impersonator_user_id?: string;
    /** T3.4 — admin's email when is_impersonation is true. */
    impersonator_email?: string;
    /** T3.4 — impersonation_grants row id when is_impersonation is true. */
    imp_grant_id?: string;
} & TClaims;
/**
 * Verifier wraps a remote JWKS fetcher with caching. Spawn one per
 * `apiUrl` and reuse — fetching JWKS on every request is wasteful.
 */
declare class JwtVerifier {
    private readonly apiUrl;
    private readonly issuer;
    private readonly audience;
    private readonly jwks;
    constructor(apiUrl: string, issuer: string, audience: string);
    /**
     * Verify an Authio access token. `TClaims` is the type of the
     * customer's custom claims (T2.4). Defaults to an empty record
     * for callers that haven't configured custom claims.
     */
    verify<TClaims extends Record<string, unknown> = Record<string, never>>(token: string): Promise<AuthioClaims<TClaims>>;
}

interface User {
    id: string;
    projectId: string;
    email: string;
    emailVerified: boolean;
    name?: string;
    avatarUrl?: string;
    defaultOrganizationId: string | null;
    createdAt: string;
    updatedAt: string;
}
interface Organization {
    id: string;
    projectId: string;
    name: string;
    slug: string;
    createdAt: string;
}
type MembershipStatus = "invited" | "active" | "suspended" | "deactivated";
interface Membership {
    id: string;
    projectId: string;
    userId: string;
    organizationId: string;
    role: string;
    status: MembershipStatus;
    joinedAt: string;
    invitedBy: string | null;
    lastActiveAt: string | null;
    preferredLoginMethod: "passkey" | "magic_link" | "oauth" | "sso" | null;
}
/**
 * A verified Authio session.
 *
 * The session always identifies the *user* (`userId`); the active
 * organization (`orgId`) is only set after the user has selected one of
 * their memberships. A user with multiple memberships may move between
 * orgs in-session without re-authenticating.
 *
 * Generic over `TClaims` so customers using the T2.4 custom-claims
 * feature get typed access to their merged claims via `claims`.
 */
interface Session<TClaims extends Record<string, unknown> = Record<string, never>> {
    sessionId: string;
    userId: string;
    orgId: string | null;
    role: string | null;
    expiresAt: string;
    /** T2.4 custom claims merged into the token. Empty when the project has no custom claims. */
    claims: TClaims;
    /** T3.4 — true when the session was minted by an Authio operator impersonating the user. */
    isImpersonation?: boolean;
    /** T3.4 — admin email when isImpersonation is true. */
    impersonatorEmail?: string;
}
/**
 * Response shape for `Authio.token({ grant_type: "client_credentials" })`
 * — the OAuth 2.0 §5.1 envelope.
 */
interface TokenResponse {
    access_token: string;
    token_type: "Bearer";
    expires_in: number;
    scope?: string;
}
interface ClientCredentialsInput {
    grant_type: "client_credentials";
    client_id: string;
    client_secret: string;
    /** Space-separated subset of the client's registered scopes. */
    scope?: string;
}
/**
 * Envelope returned by `Authio.sessions.refresh({ refreshToken })` —
 * mirrors auth-core's session.Envelope JSON shape.
 *
 * Phase 2 cookie auto-renewal: BFFs (Next.js dashboards, etc.) call
 * `refresh()` with the long-lived refresh token they stashed at sign-
 * in and use the rotated tokens to update their scoped cookies.
 *
 * The org-policy gate (idle / absolute / refresh-window / IP / geo)
 * is enforced server-side by auth-core; on a violation the call
 * throws `AuthioError` with a `policy_violation_*` code so callers
 * can render the appropriate "your admin requires re-auth" copy.
 */
interface SessionEnvelope {
    /** Auth-core session id. Stable across rotations. */
    session_id: string;
    /** New short-lived access JWT. Stash in your access cookie. */
    access_token: string;
    /** Rotated refresh token. The OLD token is now invalid. */
    refresh_token: string;
    /** ISO timestamp the access JWT expires. Use to schedule the next refresh. */
    expires_at: string;
    /** User snapshot. Convenience — same fields as Authio.users.get. */
    user: User | null;
    /** Resolved active organization, when the session has pivoted into one. */
    active_organization?: Organization | null;
    /** Active role within active_organization, when set. */
    active_role?: string;
    /** All active memberships for this user. */
    memberships?: Array<{
        id: string;
        project_id: string;
        user_id: string;
        organization_id: string;
        role: string;
        status: MembershipStatus;
    }>;
}

interface AuthioOptions {
    apiKey: string;
    apiUrl?: string;
    /**
     * The auth-core base URL (where /v1/auth/.well-known/jwks.json and
     * /v1/auth/token live). Defaults to the issuer. In production
     * Authio runs `https://identity.authio.com` here; the management
     * API at `apiUrl` runs separately at `https://manage.authio.com`.
     */
    authCoreUrl?: string;
    /** JWT issuer to require. Defaults to the production issuer. */
    jwtIssuer?: string;
    /** JWT audience to require. */
    jwtAudience?: string;
    fetch?: typeof fetch;
}
declare class Authio {
    readonly options: AuthioOptions;
    readonly users: UsersAPI;
    readonly organizations: OrganizationsAPI;
    readonly memberships: MembershipsAPI;
    readonly sessions: SessionsAPI;
    /** The auth-core base URL used for the JWKS + token endpoint. */
    readonly authCoreUrl: string;
    private readonly verifier;
    constructor(options: AuthioOptions);
    /**
     * Exchange OAuth client credentials for a short-lived access token.
     * Targets auth-core's `POST /v1/auth/token` (T2.1, RFC 6749 §4.4).
     *
     * Example:
     *
     * ```ts
     * const authio = new Authio({ apiKey: "sk_live_..." });
     * const { access_token } = await authio.token({
     *   grant_type: "client_credentials",
     *   client_id: "mci_...",
     *   client_secret: "msc_...",
     *   scope: "users:read",
     * });
     * ```
     *
     * The returned `access_token` is a Bearer JWT; pass it through
     * `authio.sessions.verify` to typecheck the claims.
     */
    token(input: ClientCredentialsInput): Promise<TokenResponse>;
    request<T>(method: string, path: string, body?: unknown): Promise<T>;
}
declare class UsersAPI {
    private readonly client;
    constructor(client: Authio);
    get(userId: string): Promise<User>;
    listMemberships(userId: string): Promise<Membership[]>;
}
declare class OrganizationsAPI {
    private readonly client;
    constructor(client: Authio);
    list(): Promise<Organization[]>;
    create(input: {
        name: string;
        slug?: string;
        domain?: string;
    }): Promise<Organization>;
    get(orgId: string): Promise<Organization>;
}
declare class MembershipsAPI {
    private readonly client;
    constructor(client: Authio);
    listForOrganization(orgId: string): Promise<Membership[]>;
    add(orgId: string, input: {
        userId: string;
        role: string;
    }): Promise<Membership>;
    remove(orgId: string, membershipId: string): Promise<void>;
}
declare class SessionsAPI {
    private readonly client;
    private readonly verifier;
    constructor(client: Authio, verifier: JwtVerifier);
    /**
     * Verify an Authio access token (JWT). Returns the typed Session, or
     * null when the token is invalid/expired.
     *
     * `session.userId` is always set; `session.orgId` may be null when the
     * user has authenticated but not yet selected an organization (multi-org
     * users coming straight out of /v1/auth/passkey/login/verify).
     *
     * `TClaims` is the type of the customer's T2.4 custom claims; pass
     * an explicit type argument to get typed access via `session.claims`.
     */
    verify<TClaims extends Record<string, unknown> = Record<string, never>>(accessToken: string): Promise<Session<TClaims> | null>;
    /** Pivot a session into a different organization without re-authentication. */
    switchOrg(_sessionId: string, input: {
        organizationId: string;
    }): Promise<Session<Record<string, never>>>;
    revoke(sessionId: string): Promise<void>;
    /**
     * Phase 2 — exchange a long-lived refresh token for a new access
     * + rotated refresh token. Targets auth-core's
     * `POST /v1/auth/refresh` (which is an alias of
     * `/v1/sessions/refresh`).
     *
     * BFFs (Next.js / Express / etc.) call this with the refresh token
     * they stashed at sign-in to silently rotate their scoped cookies
     * before the access JWT expires. The OLD refresh token is
     * one-shot — auth-core's RotateRefreshToken atomically rotates the
     * stored hash, so a stolen refresh can be replayed at most once.
     *
     * Throws `AuthioError` on:
     *   - `invalid_refresh_token` — token unknown / revoked / expired,
     *     or another concurrent refresh already rotated it.
     *   - `policy_violation_session_idle` — gap from last_active_at
     *     exceeds the org's session_idle_timeout_min.
     *   - `policy_violation_session_absolute` — session past the org's
     *     session_absolute_max_min since IssuedAt.
     *   - `policy_violation_session_refresh_window` — refresh chain
     *     past the org's refresh_window_min since IssuedAt.
     *
     * Pass the returned `access_token` to `Authio.sessions.verify` to
     * decode the merged JWT claims.
     *
     * Example:
     *
     * ```ts
     * import { Authio, AuthioError } from "@authio/node";
     *
     * const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });
     * try {
     *   const env = await authio.sessions.refresh({
     *     refreshToken: req.cookies["authio_refresh"],
     *   });
     *   res.cookie("authio_session", env.access_token, { httpOnly: true });
     *   res.cookie("authio_refresh", env.refresh_token, { httpOnly: true });
     * } catch (err) {
     *   if (err instanceof AuthioError && err.code.startsWith("policy_violation_")) {
     *     // Surface "your admin requires re-auth" copy and bounce to /sign-in.
     *   }
     *   throw err;
     * }
     * ```
     */
    refresh(input: {
        refreshToken: string;
    }): Promise<SessionEnvelope>;
}

declare class AuthioError extends Error {
    readonly code: string;
    readonly status: number;
    readonly requestId?: string;
    constructor(opts: {
        code: string;
        message: string;
        status: number;
        requestId?: string;
    });
}

export { Authio, type AuthioClaims, AuthioError, type AuthioOptions, type ClientCredentialsInput, JwtVerifier, type Membership, type Organization, type Session, type SessionEnvelope, type TokenResponse, type User };
