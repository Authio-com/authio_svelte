import { describe, expect, it, vi } from "vitest";
import { verifySessionCookie } from "../src/server/index";

vi.mock("@useauthio/node", async () => {
  class FakeVerifier {
    async verify(token: string) {
      if (token === "bad") throw new Error("bad token");
      return {
        sub: "user_123",
        sid: "sess_abc",
        act_org: "org_xyz",
        act_role: "admin",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: "https://api.authio.com",
        aud: "authio",
        custom_claim: "value",
      };
    }
  }
  return {
    JwtVerifier: FakeVerifier,
    Session: undefined,
  };
});

describe("verifySessionCookie", () => {
  it("returns null for missing token", async () => {
    expect(await verifySessionCookie(null)).toBeNull();
    expect(await verifySessionCookie(undefined)).toBeNull();
    expect(await verifySessionCookie("")).toBeNull();
  });

  it("returns null for invalid token", async () => {
    expect(await verifySessionCookie("bad")).toBeNull();
  });

  it("returns a typed Session for a valid token", async () => {
    const s = await verifySessionCookie("good");
    expect(s).not.toBeNull();
    expect(s!.userId).toBe("user_123");
    expect(s!.sessionId).toBe("sess_abc");
    expect(s!.orgId).toBe("org_xyz");
    expect(s!.role).toBe("admin");
    expect((s!.claims as Record<string, unknown>).custom_claim).toBe("value");
    expect((s!.claims as Record<string, unknown>).iss).toBeUndefined();
  });
});
