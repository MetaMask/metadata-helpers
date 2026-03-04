import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";

import {
  derivePubKey,
  encodeEd25519Point,
  generateAddressFromPrivKey,
  generateAddressFromPubKey,
  generatePrivateKey,
  getEd25519,
  getEd25519ExtendedPublicKey,
  getKeyCurve,
  getPostboxKeyFrom1OutOf1,
  getSecp256k1,
  getSecp256k1PublicKeyFromAffinePoint,
  getSecpKeyFromEd25519,
  keccak256Bytes,
  keccak256HexString,
} from "../src/helpers/crypto";

describe("getSecp256k1 / getEd25519 / getKeyCurve", () => {
  it("returns secp256k1 curve", () => {
    expect(getSecp256k1()).toBe(secp256k1);
  });

  it("returns ed25519 curve", () => {
    expect(getEd25519()).toBe(ed25519);
  });

  it("resolves keyType to curve", () => {
    expect(getKeyCurve("secp256k1")).toBe(secp256k1);
    expect(getKeyCurve("ed25519")).toBe(ed25519);
  });

  it("throws for invalid keyType", () => {
    // @ts-expect-error invalid type
    expect(() => getKeyCurve("invalid")).toThrow("Invalid keyType");
  });
});

describe("derivePubKey", () => {
  it("derives secp256k1 public key from known scalar", () => {
    const sk = 1n;
    const point = derivePubKey(secp256k1, sk);
    // G point for secp256k1
    expect(point.x).toBe(secp256k1.Point.BASE.x);
    expect(point.y).toBe(secp256k1.Point.BASE.y);
  });

  it("derives ed25519 public key from known scalar", () => {
    const sk = 1n;
    const point = derivePubKey(ed25519, sk);
    expect(point.x).toBe(ed25519.Point.BASE.x);
    expect(point.y).toBe(ed25519.Point.BASE.y);
  });
});

describe("generatePrivateKey", () => {
  it("generates 32-byte secp256k1 key", () => {
    const key = generatePrivateKey("secp256k1");
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("generates 32-byte ed25519 key", () => {
    const key = generatePrivateKey("ed25519");
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("accepts curve object directly", () => {
    const key = generatePrivateKey(secp256k1);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("generates different keys each time", () => {
    const k1 = generatePrivateKey("secp256k1");
    const k2 = generatePrivateKey("secp256k1");
    expect(bytesToHex(k1)).not.toBe(bytesToHex(k2));
  });
});

describe("keccak256HexString / keccak256Bytes", () => {
  const input = new TextEncoder().encode("hello");
  const expectedHex = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

  it("returns 0x-prefixed hex string", () => {
    expect(keccak256HexString(input)).toBe(expectedHex);
  });

  it("returns raw bytes", () => {
    const bytes = keccak256Bytes(input);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
    expect(`0x${bytesToHex(bytes)}`).toBe(expectedHex);
  });
});

describe("getEd25519ExtendedPublicKey", () => {
  it("derives ed25519 extended public key from 32-byte seed", () => {
    const seed = generatePrivateKey("ed25519");
    const result = getEd25519ExtendedPublicKey(seed);
    expect(result.scalar).toBeTypeOf("bigint");
    expect(result.scalar > 0n).toBe(true);
    expect(result.point.x).toBeTypeOf("bigint");
    expect(result.point.y).toBeTypeOf("bigint");
  });

  it("throws for wrong length seed", () => {
    expect(() => getEd25519ExtendedPublicKey(new Uint8Array(16))).toThrow("Invalid seed for ed25519 key derivation");
  });

  it("produces deterministic output", () => {
    const seed = new Uint8Array(32).fill(42);
    const r1 = getEd25519ExtendedPublicKey(seed);
    const r2 = getEd25519ExtendedPublicKey(seed);
    expect(r1.scalar).toBe(r2.scalar);
    expect(r1.point.x).toBe(r2.point.x);
    expect(r1.point.y).toBe(r2.point.y);
  });
});

describe("encodeEd25519Point", () => {
  it("encodes an ed25519 point to 32 bytes", () => {
    const seed = new Uint8Array(32).fill(1);
    const { point } = getEd25519ExtendedPublicKey(seed);
    const encoded = encodeEd25519Point(point);
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBe(32);
  });
});

describe("getSecpKeyFromEd25519", () => {
  it("derives secp256k1 key from ed25519 scalar", () => {
    const seed = new Uint8Array(32).fill(7);
    const { scalar: ed25519Scalar } = getEd25519ExtendedPublicKey(seed);
    const result = getSecpKeyFromEd25519(ed25519Scalar);

    expect(result.scalar).toBeTypeOf("bigint");
    expect(result.scalar > 0n).toBe(true);
    expect(result.point.x).toBeTypeOf("bigint");
    expect(result.point.y).toBeTypeOf("bigint");

    // Verify the point is on secp256k1
    const reconstructed = secp256k1.Point.fromAffine(result.point);
    expect(() => reconstructed.assertValidity()).not.toThrow();
  });
});

describe("getSecp256k1PublicKeyFromAffinePoint", () => {
  it("returns 64-byte uncompressed key without 04 prefix", () => {
    const sk = 42n;
    const point = derivePubKey(secp256k1, sk);
    const pubKey = getSecp256k1PublicKeyFromAffinePoint(point);
    expect(pubKey).toBeInstanceOf(Uint8Array);
    expect(pubKey.length).toBe(64);
  });
});

describe("generateAddressFromPrivKey / generateAddressFromPubKey", () => {
  it("generates consistent secp256k1 address from priv and pub key", () => {
    const sk = 42n;
    const point = derivePubKey(secp256k1, sk);
    const addrFromPriv = generateAddressFromPrivKey("secp256k1", sk);
    const addrFromPub = generateAddressFromPubKey("secp256k1", point.x, point.y);
    expect(addrFromPriv).toBe(addrFromPub);
    expect(addrFromPriv).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it("generates ed25519 address (base58)", () => {
    const seed = new Uint8Array(32).fill(1);
    const { scalar, point } = getEd25519ExtendedPublicKey(seed);
    const addr = generateAddressFromPrivKey("ed25519", scalar);
    expect(addr.length).toBeGreaterThan(0);
    const addrFromPub = generateAddressFromPubKey("ed25519", point.x, point.y);
    expect(addr).toBe(addrFromPub);
  });
});

describe("getPostboxKeyFrom1OutOf1", () => {
  it("computes privKey - nonce mod n", () => {
    const privKey = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    const nonce = "0000000000000000000000000000000000000000000000000000000000000001";
    const result = getPostboxKeyFrom1OutOf1(secp256k1, privKey, nonce);
    expect(result.length).toBe(64);
    expect(typeof result).toBe("string");
  });

  it("handles hex with 0x prefix", () => {
    const privKey = "0x05";
    const nonce = "0x02";
    const result = getPostboxKeyFrom1OutOf1(secp256k1, privKey, nonce);
    expect(BigInt(`0x${result}`)).toBe(3n);
  });
});
