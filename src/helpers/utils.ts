import { invert, mod } from "@noble/curves/abstract/modular.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, bytesToNumberBE, bytesToNumberLE, numberToBytesBE, numberToHexUnpadded } from "@noble/curves/utils.js";

export { bytesToHex, bytesToNumberBE, bytesToNumberLE, invert, mod, numberToBytesBE, numberToHexUnpadded };

export { secp256k1 };
export { sha512 } from "@noble/hashes/sha2.js";
export { keccak_256 } from "@noble/hashes/sha3.js";

export function toEthereumSignature(recoveredSig: Uint8Array): Uint8Array {
  const ethSig = new Uint8Array(65);
  ethSig.set(recoveredSig.slice(1, 65), 0); // r + s
  ethSig[64] = recoveredSig[0]; // v at end
  return ethSig;
}

export function getPublicKeyCoords(privateKeyBytes: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const pubKeyUncompressed = secp256k1.getPublicKey(privateKeyBytes, false);
  const x = pubKeyUncompressed.slice(1, 33);
  const y = pubKeyUncompressed.slice(33, 65);
  return { x, y };
}

export function coordsToPublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  const pubKey = new Uint8Array(65);
  pubKey[0] = 0x04; // uncompressed prefix
  pubKey.set(x, 1);
  pubKey.set(y, 33);
  return pubKey;
}
