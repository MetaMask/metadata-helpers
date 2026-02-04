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

export { bytesToHex, hexToBytes, secp256k1 };
