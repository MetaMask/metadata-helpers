import { describe, expect, it } from "vitest";

import { base64url, bytesToBase64, utf8ToBytes } from "../src/utils";

// Bytes chosen to produce +, /, and = in standard base64
const testBytes = new Uint8Array([0xfb, 0xef, 0xff, 0xfe, 0xfd]);

describe("base64url", () => {
  it("should not contain +, /, or = characters", () => {
    const b64url = base64url(testBytes);
    expect(b64url).not.toContain("+");
    expect(b64url).not.toContain("/");
    expect(b64url).not.toContain("=");
  });

  it("should replace + with - and / with _", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = base64url(testBytes);
    const expected = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    expect(b64url).toBe(expected);
  });

  it("should convert from base64url to base64", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = base64url(testBytes);
    const result = base64url.toBase64(b64url);
    expect(result).toBe(b64);
  });

  it("should convert from base64 to base64url", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = base64url(testBytes);
    const result = base64url.fromBase64(b64);
    expect(result).toBe(b64url);
  });

  it("should decode base64url to utf8 string", () => {
    const original = "Hello, World! 🌍 Special chars: àéîõü";
    const b64url = base64url(original);
    const result = base64url.decode(b64url);
    expect(result).toBe(original);
  });

  it("should handle toBase64 with Uint8Array input", () => {
    const original = "Hello, World!";
    const b64url = base64url(original);
    const b64urlBytes = utf8ToBytes(b64url);
    const result = base64url.toBase64(b64urlBytes);
    expect(result).toBe(base64url.toBase64(b64url));
  });

  it("should convert to Uint8Array via toBufferLike", () => {
    const original = "Hello, World!";
    const b64url = base64url(original);
    const result = base64url.toBufferLike(b64url);
    expect(result).toEqual(utf8ToBytes(original));
  });

  it("should encode and decode correctly", () => {
    const original = "ladies and gentlemen, we are floating in space";
    const encoded = "bGFkaWVzIGFuZCBnZW50bGVtZW4sIHdlIGFyZSBmbG9hdGluZyBpbiBzcGFjZQ";
    expect(base64url.encode(original)).toBe(encoded);
    expect(base64url.decode(encoded)).toBe(original);
  });
});
