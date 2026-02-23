import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";

export function keccak256(data: Uint8Array): Uint8Array {
  return keccakHash(data);
}

export function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function bytesToBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join("");
  return btoa(binString);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  return Uint8Array.from(binString, (ch) => ch.codePointAt(0)!);
}

// Convert noble-curves recovered format (v || r || s) to Ethereum format (r || s || v)
export function toEthereumSignature(recoveredSig: Uint8Array): Uint8Array {
  const ethSig = new Uint8Array(65);
  ethSig.set(recoveredSig.slice(1, 65), 0); // r + s
  ethSig[64] = recoveredSig[0]; // v at end
  return ethSig;
}

export function getPublicKeyCoords(privateKeyHex: string): { x: string; y: string } {
  const privKeyBytes = hexToBytes(privateKeyHex.padStart(64, "0"));
  const pubKeyUncompressed = secp256k1.getPublicKey(privKeyBytes, false);
  const x = bytesToHex(pubKeyUncompressed.slice(1, 33));
  const y = bytesToHex(pubKeyUncompressed.slice(33, 65));
  return { x, y };
}

export function coordsToPublicKey(x: string, y: string): Uint8Array {
  const xBytes = hexToBytes(x.padStart(64, "0"));
  const yBytes = hexToBytes(y.padStart(64, "0"));
  const pubKey = new Uint8Array(65);
  pubKey[0] = 0x04; // uncompressed prefix
  pubKey.set(xBytes, 1);
  pubKey.set(yBytes, 33);
  return pubKey;
}

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
function encode(input: string | Uint8Array): string {
  if (input instanceof Uint8Array) {
    return fromBase64(bytesToBase64(input));
  }
  return fromBase64(bytesToBase64(utf8ToBytes(input)));
}

/**
 * Decode a base64url string to a string or Uint8Array.
 * @param base64url - The base64url string to decode.
 * @returns The decoded string or Uint8Array.
 */
function decode(base64url: string): string {
  return bytesToUtf8(base64ToBytes(toBase64(base64url)));
}

/**
 * Convert a base64url string to a base64 string.
 * @param base64url - The base64url string or Uint8Array (will be converted to string utf8 encoding) to convert.
 * @returns The base64 string.
 */
function toBase64(base64url: string | Uint8Array): string {
  const urlString = base64url instanceof Uint8Array ? bytesToUtf8(base64url) : base64url;
  return padString(urlString).replace(/-/g, "+").replace(/_/g, "/");
}

/**
 * Decode a base64 string to a base64url string.
 * @param base64 - The base64 string to decode.
 * @returns The base64url string.
 */
function fromBase64(base64: string): string {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Convert a base64url string to a buffer-like object.
 * @param base64url - The base64url string to convert.
 * @returns The buffer-like object.
 */
function toBufferLike(base64url: string): Uint8Array {
  return base64ToBytes(toBase64(base64url));
}

export interface Base64Url {
  (input: string | Uint8Array): string;
  encode(input: string | Uint8Array): string;
  decode(base64url: string): string;
  toBase64(base64url: string | Uint8Array): string;
  fromBase64(base64: string): string;
  toBufferLike(base64url: string): Uint8Array;
}

const base64url = encode as Base64Url;

base64url.encode = encode;
base64url.decode = decode;
base64url.toBase64 = toBase64;
base64url.fromBase64 = fromBase64;
base64url.toBufferLike = toBufferLike;

export { base64url, bytesToHex, hexToBytes, secp256k1 };
