import type { AffinePoint as AffinePointCurve } from "@noble/curves/abstract/curve.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, bytesToNumberBE, bytesToNumberLE, numberToBytesBE } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { base58 } from "@scure/base";

import { getChecksumAddress, Hex } from "./hex";
import { bigintToHex, type HexOutputOptions, toBigIntBE } from "./number";

/** Normalize any hex string (with or without 0x) to bigint. Empty → 0n. */
export type AffinePoint = AffinePointCurve<bigint>;
export type Curve = typeof secp256k1 | typeof ed25519;
export type KeyType = "secp256k1" | "ed25519";

export const getSecp256k1 = () => secp256k1;
export const getEd25519 = () => ed25519;

export const getKeyCurve = (keyType: KeyType): Curve => {
  if (keyType === "secp256k1") return getSecp256k1();
  if (keyType === "ed25519") return getEd25519();
  throw new Error(`Invalid keyType: ${keyType}`);
};

export function derivePubKey(ecCurve: Curve, sk: bigint): AffinePoint {
  return ecCurve.Point.BASE.multiply(sk).toAffine();
}

/**
 * Generate a random private key for the given curve or key type.
 * Prefer passing ecCurve directly when you already have it (better for tree-shaking).
 */
export function generatePrivateKey(keyType: KeyType): Uint8Array;
export function generatePrivateKey(ecCurve: Curve): Uint8Array;
export function generatePrivateKey(ecCurveOrKeyType: Curve | KeyType): Uint8Array {
  const ec = typeof ecCurveOrKeyType === "string" ? getKeyCurve(ecCurveOrKeyType) : ecCurveOrKeyType;
  return ec.utils.randomSecretKey();
}

/**
 * Returns keccak256 hash as hex string (torus.js–compatible name). By default 0x-prefixed.
 * Use keccak256Bytes when you need raw bytes.
 *
 * @param a - Input bytes.
 * @param options - Optional. Set `{ prefixed: false }` to omit "0x" prefix.
 */
export function keccak256(a: Uint8Array, options?: HexOutputOptions): string {
  const hash = bytesToHex(keccak_256(a));
  return options?.prefixed === false ? hash : `0x${hash}`;
}

/** Returns keccak256 hash as raw bytes. */
export function keccak256Bytes(a: Uint8Array): Uint8Array {
  return keccak_256(a);
}

function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

/** Ed25519 extended public key derivation per RFC 8032 5.1.5 */
export function getEd25519ExtendedPublicKey(keyBytes: Uint8Array): {
  scalar: bigint;
  point: AffinePoint;
} {
  const ed25519Curve = getKeyCurve("ed25519");
  const N = ed25519Curve.Point.CURVE().n;

  if (keyBytes.length !== 32) {
    throw new Error("Invalid seed for ed25519 key derivation");
  }
  const hashed = sha512(keyBytes);
  if (hashed.length !== 64) {
    throw new Error("Invalid hash length for ed25519 seed");
  }
  const head = bytesToNumberLE(adjustScalarBytes(new Uint8Array(hashed.slice(0, 32))));
  const scalar = mod(head, N);
  const point = derivePubKey(ed25519Curve, scalar);
  return { scalar, point };
}

export function encodeEd25519Point(point: AffinePoint): Uint8Array {
  const ed25519Curve = getKeyCurve("ed25519");
  return ed25519Curve.Point.fromAffine(point).toBytes();
}

/** Derives a secp256k1 key pair from an Ed25519 scalar via keccak hash. */
export const getSecpKeyFromEd25519 = (
  ed25519Scalar: bigint
): {
  scalar: bigint;
  point: AffinePoint;
} => {
  const secp = getSecp256k1();
  const N = secp.Point.CURVE().n;

  const keyHash = keccak_256(numberToBytesBE(ed25519Scalar, 32));
  const secpScalar = mod(bytesToNumberBE(keyHash), N);
  const point = derivePubKey(secp, secpScalar);

  return { scalar: secpScalar, point };
};

/** Encodes a secp256k1 affine point as 64-byte uncompressed key (without 04 prefix). */
export function getSecp256k1PublicKeyFromAffinePoint(point: AffinePoint): Uint8Array {
  const uncompressed = getSecp256k1().Point.fromAffine(point).toBytes(false);
  return uncompressed.slice(1);
}

function generateAddressFromPoint(keyType: KeyType, point: AffinePoint): string {
  if (keyType === "secp256k1") {
    const publicKey = getSecp256k1PublicKeyFromAffinePoint(point);
    const evmAddressLower = `0x${keccak256(publicKey).slice(64 - 38)}` as Hex;
    return getChecksumAddress(evmAddressLower);
  } else if (keyType === "ed25519") {
    const publicKey = encodeEd25519Point(point);
    return base58.encode(publicKey);
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

export function generateAddressFromPrivKey(keyType: KeyType, privateKey: bigint): string {
  const ecCurve = getKeyCurve(keyType);
  const point = derivePubKey(ecCurve, privateKey);
  return generateAddressFromPoint(keyType, point);
}

export function generateAddressFromPubKey(keyType: KeyType, publicKeyX: bigint, publicKeyY: bigint): string {
  return generateAddressFromPoint(keyType, { x: publicKeyX, y: publicKeyY });
}

/**
 * Derive postbox key: privKey - nonce (mod n).
 * Inputs accept hex with or without 0x prefix.
 * By default returns raw hex (no prefix) for backward compat.
 *
 * @param options - Optional. Set `{ prefixed: true }` to add "0x" prefix.
 */
export function getPostboxKeyFrom1OutOf1(ecCurve: Curve, privKey: string, nonce: string, options?: HexOutputOptions): string {
  const privKeyBI = toBigIntBE(privKey);
  const nonceBI = toBigIntBE(nonce);
  const n = ecCurve.Point.CURVE().n;
  const result = mod(privKeyBI - nonceBI, n);
  return bigintToHex(result, 64, options);
}
