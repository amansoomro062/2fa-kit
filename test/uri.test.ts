import { describe, expect, it } from "vitest";
import { buildUri, parseUri } from "../src/uri.js";

const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("buildUri", () => {
  it("builds a minimal totp URI", () => {
    expect(buildUri({ label: "alice@example.com", secret: SECRET })).toBe(
      `otpauth://totp/alice%40example.com?secret=${SECRET}`,
    );
  });

  it("prefixes the label with the issuer when no prefix is present", () => {
    const uri = buildUri({ label: "alice@example.com", secret: SECRET, issuer: "Acme" });
    expect(uri).toBe(`otpauth://totp/Acme%3Aalice%40example.com?secret=${SECRET}&issuer=Acme`);
  });

  it("does not double-prefix when the label already contains a colon", () => {
    const uri = buildUri({ label: "Acme:alice", secret: SECRET, issuer: "Acme" });
    expect(uri).toBe(`otpauth://totp/Acme%3Aalice?secret=${SECRET}&issuer=Acme`);
  });

  it("encodes labels with colons and spaces", () => {
    const uri = buildUri({ label: "Acme Corp:Alice A.", secret: SECRET });
    expect(uri).toContain("Acme%20Corp%3AAlice%20A.");
    const parsed = parseUri(uri);
    expect(parsed.label).toBe("Alice A.");
    expect(parsed.issuer).toBe("Acme Corp");
  });

  it("includes optional totp parameters", () => {
    const uri = buildUri({
      label: "alice",
      secret: SECRET,
      issuer: "Acme",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
    const url = new URL(uri);
    expect(url.searchParams.get("algorithm")).toBe("SHA256");
    expect(url.searchParams.get("digits")).toBe("8");
    expect(url.searchParams.get("period")).toBe("60");
  });

  it("requires counter for hotp URIs", () => {
    expect(() => buildUri({ label: "alice", secret: SECRET, type: "hotp" })).toThrow(TypeError);
    const uri = buildUri({ label: "alice", secret: SECRET, type: "hotp", counter: 5 });
    expect(uri.startsWith("otpauth://hotp/")).toBe(true);
    expect(new URL(uri).searchParams.get("counter")).toBe("5");
  });
});

describe("parseUri", () => {
  it("round-trips a full totp URI", () => {
    const uri = buildUri({
      label: "alice@example.com",
      secret: SECRET,
      issuer: "Acme",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
    expect(parseUri(uri)).toEqual({
      type: "totp",
      label: "alice@example.com",
      issuer: "Acme",
      secret: SECRET,
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
  });

  it("round-trips a hotp URI with counter", () => {
    const uri = buildUri({ label: "bob", secret: SECRET, type: "hotp", counter: 42 });
    expect(parseUri(uri)).toEqual({
      type: "hotp",
      label: "bob",
      secret: SECRET,
      counter: 42,
    });
  });

  it("reads issuer from the label prefix when no issuer param exists", () => {
    const parsed = parseUri(`otpauth://totp/Acme%20Corp:alice%40example.com?secret=${SECRET}`);
    expect(parsed.label).toBe("alice@example.com");
    expect(parsed.issuer).toBe("Acme Corp");
  });

  it("prefers the issuer parameter over the label prefix", () => {
    const parsed = parseUri(`otpauth://totp/Old:alice?secret=${SECRET}&issuer=New`);
    expect(parsed.issuer).toBe("New");
  });

  it("rejects malformed URIs", () => {
    expect(() => parseUri("not a uri")).toThrow(TypeError);
    expect(() => parseUri("https://totp/alice?secret=ABC")).toThrow(TypeError);
    expect(() => parseUri("otpauth://foo/alice?secret=ABC")).toThrow(TypeError);
    expect(() => parseUri("otpauth://totp/alice")).toThrow(TypeError);
    expect(() => parseUri(`otpauth://hotp/alice?secret=${SECRET}`)).toThrow(TypeError);
  });
});
