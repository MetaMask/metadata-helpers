import { base64ToBytes, bytesToBase64 } from "./bytes";
import { bytesToUtf8, utf8ToBytes } from "./utils";

/**
 * Pad a string to a multiple of segment length (4 for base64url).
 * @param input - The string to pad.
 * @returns The padded string.
 */
function padString(input: string): string {
  const segmentLength = 4;
  const diff = input.length % segmentLength;
  if (!diff) {
    return input;
  }
  return input + "=".repeat(segmentLength - diff);
}

/**
 * Encode a string or Uint8Array to a base64url string.
 * @param input - The string (only support utf8 encoding) or Uint8Array to encode.
 * @returns The base64url string.
 */
export function encodeBase64Url(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return fromBase64(bytesToBase64(bytes));
}

/**
 * Decode a base64url string to a string or Uint8Array.
 * @param base64url - The base64url string to decode.
 * @returns The decoded string or Uint8Array.
 */
export function decodeBase64Url(base64url: string): string {
  return bytesToUtf8(base64ToBytes(toBase64(base64url)));
}

/**
 * Convert a base64url string to a base64 string.
 * @param base64url - The base64url string or Uint8Array (will be converted to string utf8 encoding) to convert.
 * @returns The base64 string.
 */
export function toBase64(base64url: string | Uint8Array): string {
  const urlString = base64url instanceof Uint8Array ? bytesToUtf8(base64url) : base64url;
  return padString(urlString).replace(/-/g, "+").replace(/_/g, "/");
}

/**
 * Decode a base64 string to a base64url string.
 * @param base64 - The base64 string to decode.
 * @returns The base64url string.
 */
export function fromBase64(base64: string): string {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Convert a base64url string to a buffer-like object.
 * @param base64url - The base64url string to convert.
 * @returns The buffer-like object.
 */
export function toBufferLike(base64url: string): Uint8Array {
  return base64ToBytes(toBase64(base64url));
}
