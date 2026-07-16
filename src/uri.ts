/**
 * otpauth:// URI building and parsing, per the Key URI Format used by
 * Google Authenticator and compatible apps:
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */

export interface ParsedOtpauth {
  type: "totp" | "hotp";
  /** The account label (everything after `otpauth://<type>/`, decoded). */
  label: string;
  /** Issuer, from the `issuer` parameter or an `Issuer:` label prefix. */
  issuer?: string;
  /** base32-encoded shared secret. */
  secret: string;
  algorithm?: string;
  digits?: number;
  /** TOTP only: time step in seconds. */
  period?: number;
  /** HOTP only: initial counter. */
  counter?: number;
}

export interface BuildUriOptions {
  /** Account label, e.g. "alice@example.com" or "Acme:alice@example.com". */
  label: string;
  /** base32-encoded shared secret. */
  secret: string;
  /** Issuer name; added as a query parameter. */
  issuer?: string;
  /** OTP type (default "totp"). */
  type?: "totp" | "hotp";
  /** HMAC algorithm, e.g. "SHA1", "SHA256", "SHA512" (default omitted = SHA1). */
  algorithm?: string;
  /** Code length (default omitted = 6). */
  digits?: number;
  /** TOTP time step in seconds (default omitted = 30). */
  period?: number;
  /** HOTP initial counter (required for type "hotp"). */
  counter?: number;
}

/** Build an otpauth:// URI suitable for encoding into a QR code. */
export function buildUri(opts: BuildUriOptions): string {
  const { label, secret, issuer, type = "totp", algorithm, digits, period, counter } = opts;
  if (!label) {
    throw new TypeError("label is required");
  }
  if (!secret) {
    throw new TypeError("secret is required");
  }
  if (type === "hotp" && (counter === undefined || counter === null)) {
    throw new TypeError("counter is required for hotp URIs");
  }

  const pathLabel = issuer && !label.includes(":") ? `${issuer}:${label}` : label;
  const params = new URLSearchParams({ secret });
  if (issuer) params.set("issuer", issuer);
  if (algorithm) params.set("algorithm", algorithm);
  if (digits !== undefined) params.set("digits", String(digits));
  if (type === "totp" && period !== undefined) params.set("period", String(period));
  if (type === "hotp" && counter !== undefined) params.set("counter", String(counter));

  return `otpauth://${type}/${encodeURIComponent(pathLabel)}?${params.toString()}`;
}

/** Parse an otpauth://totp or otpauth://hotp URI. */
export function parseUri(uri: string): ParsedOtpauth {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new TypeError(`Invalid otpauth URI: ${uri}`);
  }
  if (url.protocol !== "otpauth:") {
    throw new TypeError(`Expected otpauth: protocol, got ${url.protocol}`);
  }
  const type = url.host.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    throw new TypeError(`Unsupported otpauth type: ${type}`);
  }

  const rawLabel = decodeURIComponent(url.pathname.replace(/^\//, ""));
  let label = rawLabel;
  let prefixIssuer: string | undefined;
  const colonIndex = rawLabel.indexOf(":");
  if (colonIndex > 0) {
    prefixIssuer = rawLabel.slice(0, colonIndex);
    label = rawLabel.slice(colonIndex + 1);
  }

  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) {
    throw new TypeError("otpauth URI is missing the secret parameter");
  }

  const issuer = params.get("issuer") ?? prefixIssuer;
  const algorithm = params.get("algorithm") ?? undefined;

  const digitsParam = params.get("digits");
  const digits = digitsParam === null ? undefined : parseIntParam("digits", digitsParam);
  const periodParam = params.get("period");
  const period = periodParam === null ? undefined : parseIntParam("period", periodParam);
  const counterParam = params.get("counter");
  const counter = counterParam === null ? undefined : parseIntParam("counter", counterParam);

  if (type === "hotp" && counter === undefined) {
    throw new TypeError("hotp otpauth URI is missing the counter parameter");
  }

  const result: ParsedOtpauth = { type, label, secret };
  if (issuer !== undefined) result.issuer = issuer;
  if (algorithm !== undefined) result.algorithm = algorithm;
  if (digits !== undefined) result.digits = digits;
  if (period !== undefined) result.period = period;
  if (counter !== undefined) result.counter = counter;
  return result;
}

function parseIntParam(name: string, value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new TypeError(`Invalid ${name} parameter: ${value}`);
  }
  return n;
}
