// src/errors.ts
var AuthioError = class extends Error {
  code;
  status;
  requestId;
  constructor(opts) {
    super(opts.message);
    this.name = "AuthioError";
    this.code = opts.code;
    this.status = opts.status;
    this.requestId = opts.requestId;
  }
};

// src/jwks.ts
import { createRemoteJWKSet, jwtVerify } from "jose";
var JwtVerifier = class {
  constructor(apiUrl, issuer, audience) {
    this.apiUrl = apiUrl;
    this.issuer = issuer;
    this.audience = audience;
    this.jwks = createRemoteJWKSet(
      new URL(this.apiUrl.replace(/\/$/, "") + "/v1/auth/.well-known/jwks.json"),
      {
        cooldownDuration: 3e4,
        cacheMaxAge: 6e5
      }
    );
  }
  apiUrl;
  issuer;
  audience;
  jwks;
  /**
   * Verify an Authio access token. `TClaims` is the type of the
   * customer's custom claims (T2.4). Defaults to an empty record
   * for callers that haven't configured custom claims.
   */
  async verify(token) {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.issuer,
      audience: this.audience,
      algorithms: ["EdDSA"]
    });
    if (!payload.sub) {
      throw new Error("authio: token missing sub claim");
    }
    return payload;
  }
};

// src/client.ts
var DEFAULT_API_URL = "https://manage.authio.com";
var DEFAULT_ISSUER = "https://identity.authio.com";
var DEFAULT_AUDIENCE = "authio";
var Authio = class {
  constructor(options) {
    this.options = options;
    if (!options.apiKey) {
      throw new Error(
        "Authio: apiKey is required. Pass it directly or set AUTHIO_SECRET_KEY."
      );
    }
    const apiUrl = options.apiUrl ?? DEFAULT_API_URL;
    this.authCoreUrl = (options.authCoreUrl ?? options.jwtIssuer ?? DEFAULT_ISSUER).replace(
      /\/$/,
      ""
    );
    this.verifier = new JwtVerifier(
      this.authCoreUrl,
      options.jwtIssuer ?? DEFAULT_ISSUER,
      options.jwtAudience ?? DEFAULT_AUDIENCE
    );
    this.sessions = new SessionsAPI(this, this.verifier);
  }
  options;
  users = new UsersAPI(this);
  organizations = new OrganizationsAPI(this);
  memberships = new MembershipsAPI(this);
  sessions;
  /** The auth-core base URL used for the JWKS + token endpoint. */
  authCoreUrl;
  verifier;
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
  async token(input) {
    const fetchFn = this.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(`${this.authCoreUrl}/v1/auth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0"
      },
      body: JSON.stringify(input)
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new AuthioError({
        code: data.error ?? "token_request_failed",
        message: data.error_description ?? `Token endpoint returned status ${res.status}`,
        status: res.status
      });
    }
    return await res.json();
  }
  async request(method, path, body) {
    const url = (this.options.apiUrl ?? DEFAULT_API_URL) + path;
    const fetchFn = this.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(url, {
      method,
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0",
        authorization: `Bearer ${this.options.apiKey}`
      },
      body: body ? JSON.stringify(body) : void 0
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new AuthioError({
        code: data.code ?? "request_failed",
        message: data.message ?? `Request failed with status ${res.status}`,
        status: res.status,
        requestId: data.request_id
      });
    }
    if (res.status === 204) return void 0;
    return await res.json();
  }
};
var UsersAPI = class {
  constructor(client) {
    this.client = client;
  }
  client;
  get(userId) {
    return this.client.request("GET", `/v1/users/${userId}`);
  }
  listMemberships(userId) {
    return this.client.request(
      "GET",
      `/v1/users/${userId}/memberships`
    );
  }
};
var OrganizationsAPI = class {
  constructor(client) {
    this.client = client;
  }
  client;
  list() {
    return this.client.request("GET", "/v1/organizations");
  }
  create(input) {
    return this.client.request("POST", "/v1/organizations", input);
  }
  get(orgId) {
    return this.client.request("GET", `/v1/organizations/${orgId}`);
  }
};
var MembershipsAPI = class {
  constructor(client) {
    this.client = client;
  }
  client;
  listForOrganization(orgId) {
    return this.client.request(
      "GET",
      `/v1/organizations/${orgId}/memberships`
    );
  }
  add(orgId, input) {
    return this.client.request(
      "POST",
      `/v1/organizations/${orgId}/memberships`,
      { user_id: input.userId, role: input.role }
    );
  }
  remove(orgId, membershipId) {
    return this.client.request(
      "DELETE",
      `/v1/organizations/${orgId}/memberships/${membershipId}`
    );
  }
};
var RESERVED_JWT_CLAIMS = /* @__PURE__ */ new Set([
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
  "imp_grant_id"
]);
var SessionsAPI = class {
  constructor(client, verifier) {
    this.client = client;
    this.verifier = verifier;
  }
  client;
  verifier;
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
  async verify(accessToken) {
    if (!accessToken) return null;
    try {
      const claims = await this.verifier.verify(accessToken);
      const merged = {};
      for (const [k, v] of Object.entries(claims)) {
        if (RESERVED_JWT_CLAIMS.has(k)) continue;
        merged[k] = v;
      }
      return {
        sessionId: claims.sid ?? "",
        userId: claims.sub,
        orgId: claims.act_org ? claims.act_org : null,
        role: claims.act_role ? claims.act_role : null,
        expiresAt: claims.exp ? new Date(claims.exp * 1e3).toISOString() : (/* @__PURE__ */ new Date()).toISOString(),
        claims: merged,
        isImpersonation: claims.is_impersonation === true ? true : void 0,
        impersonatorEmail: claims.impersonator_email ?? void 0
      };
    } catch {
      return null;
    }
  }
  /** Pivot a session into a different organization without re-authentication. */
  switchOrg(_sessionId, input) {
    return this.client.request(
      "POST",
      "/v1/sessions/switch-org",
      { organization_id: input.organizationId }
    );
  }
  revoke(sessionId) {
    return this.client.request("POST", "/v1/sessions/revoke", {
      session_id: sessionId
    });
  }
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
   * import { Authio, AuthioError } from "@useauthio/node";
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
  async refresh(input) {
    if (!input?.refreshToken) {
      throw new AuthioError({
        code: "missing_refresh_token",
        message: "Authio.sessions.refresh: refreshToken is required",
        status: 400
      });
    }
    const fetchFn = this.client.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(`${this.client.authCoreUrl}/v1/auth/refresh`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0"
      },
      body: JSON.stringify({ refresh_token: input.refreshToken })
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new AuthioError({
        code: body.code ?? body.error ?? "refresh_failed",
        message: body.message ?? `Refresh request failed with status ${res.status}`,
        status: res.status,
        requestId: body.request_id
      });
    }
    return await res.json();
  }
};
export {
  Authio,
  AuthioError,
  JwtVerifier
};
