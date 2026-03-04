import { describe, expect, it } from "vitest";

import { bytesToBase64 } from "../src";
import { decodeBase64Url, encodeBase64Url, fromBase64, toBase64, toBufferLike } from "../src/helpers/base64url";
import { utf8ToBytes } from "../src/helpers/utils";

const testBytes = new Uint8Array([0xfb, 0xef, 0xff, 0xfe, 0xfd]);

describe("base64url", () => {
  it("should not contain +, /, or = characters", () => {
    const b64url = encodeBase64Url(testBytes);
    expect(b64url).not.toContain("+");
    expect(b64url).not.toContain("/");
    expect(b64url).not.toContain("=");
  });

  it("should replace + with - and / with _", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = encodeBase64Url(testBytes);
    const expected = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    expect(b64url).toBe(expected);
  });

  it("should convert from base64url to base64", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = encodeBase64Url(testBytes);
    const result = toBase64(b64url);
    expect(result).toBe(b64);
  });

  it("should convert from base64 to base64url", () => {
    const b64 = bytesToBase64(testBytes);
    const b64url = encodeBase64Url(testBytes);
    const result = fromBase64(b64);
    expect(result).toBe(b64url);
  });

  it("should decode base64url to utf8 string", () => {
    const original = "Hello, World! 🌍 Special chars: àéîõü";
    const b64url = encodeBase64Url(original);
    const result = decodeBase64Url(b64url);
    expect(result).toBe(original);
  });

  it("should handle toBase64 with Uint8Array input", () => {
    const original = "Hello, World!";
    const b64url = encodeBase64Url(original);
    const b64urlBytes = utf8ToBytes(b64url);
    const result = toBase64(b64urlBytes);
    expect(result).toBe(toBase64(b64url));
  });

  it("should convert to Uint8Array via toBufferLike", () => {
    const original = "Hello, World!";
    const b64url = encodeBase64Url(original);
    const result = toBufferLike(b64url);
    expect(result).toEqual(utf8ToBytes(original));
  });

  it("should encode and decode correctly", () => {
    const original = "ladies and gentlemen, we are floating in space";
    const encoded = "bGFkaWVzIGFuZCBnZW50bGVtZW4sIHdlIGFyZSBmbG9hdGluZyBpbiBzcGFjZQ";
    expect(encodeBase64Url(original)).toBe(encoded);
    expect(decodeBase64Url(encoded)).toBe(original);
  });
});
