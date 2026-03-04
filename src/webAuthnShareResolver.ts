import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { decrypt, Ecies, encrypt, getPublic } from "@toruslabs/eccrypto";

import { bytesToUtf8, coordsToPublicKey, getPublicKeyCoords, utf8ToBytes } from "./helpers/utils";
import { MetadataStorageLayer, PubKeyParams } from "./MetadataStorageLayer";

const WEBAUTHN_TORUS_SHARE = "webauthn_torus_share";
const WEBAUTHN_DEVICE_SHARE = "webauthn_device_share";

export type EciesHex = {
  iv: string;
  ephemPublicKey: string;
  ciphertext: string;
  mac: string;
};

export function encParamsHexToBuf(encParamsHex: EciesHex): Ecies {
  return {
    iv: hexToBytes(encParamsHex.iv),
    ephemPublicKey: hexToBytes(encParamsHex.ephemPublicKey),
    ciphertext: hexToBytes(encParamsHex.ciphertext),
    mac: hexToBytes(encParamsHex.mac),
  };
}

export function encParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: bytesToHex(encParams.iv),
    ephemPublicKey: bytesToHex(encParams.ephemPublicKey),
    ciphertext: bytesToHex(encParams.ciphertext),
    mac: bytesToHex(encParams.mac),
  };
}

export async function encryptData(privKeyBytes: Uint8Array, d: unknown): Promise<string> {
  const serializedData = utf8ToBytes(JSON.stringify(d));
  const encParams = await encrypt(getPublic(privKeyBytes), serializedData);
  const encParamsHex = encParamsBufToHex(encParams);
  return JSON.stringify(encParamsHex);
}

export async function decryptData<T>(privKeyBytes: Uint8Array, d: string): Promise<T> {
  const encParamsHex: EciesHex = JSON.parse(d);
  const encParams = encParamsHexToBuf(encParamsHex);
  const serializedBytes = await decrypt(privKeyBytes, encParams);
  const data: T = JSON.parse(bytesToUtf8(serializedBytes));
  return data;
}

export async function getAndDecryptData<T>(m: MetadataStorageLayer, privKeyBytes: Uint8Array, namespace: string): Promise<Record<string, T> | null> {
  const { x, y } = getPublicKeyCoords(privKeyBytes);
  const serializedData = await m.getMetadata({ pub_key_X: x, pub_key_Y: y }, namespace);
  if (!serializedData) {
    return null;
  }
  const data = await decryptData<T>(privKeyBytes, serializedData);
  return data as Record<string, T>;
}

export async function encryptAndSetData(
  m: MetadataStorageLayer,
  privKeyBytes: Uint8Array,
  d: Record<string, unknown>,
  namespace: string
): Promise<void> {
  const sData = await encryptData(privKeyBytes, d);
  const metadataParams = m.generateMetadataParams(sData, privKeyBytes);
  await m.setMetadata(metadataParams, namespace);
}

export async function setTorusShare(
  m: MetadataStorageLayer,
  webAuthnPubKey: PubKeyParams,
  webAuthnRefBytes: Uint8Array,
  subspace: string,
  subspaceData: unknown
): Promise<void> {
  const pubKeyBytes = coordsToPublicKey(webAuthnPubKey.pub_key_X, webAuthnPubKey.pub_key_Y);
  const data = await getAndDecryptData(m, webAuthnRefBytes, WEBAUTHN_TORUS_SHARE);
  let d: Record<string, unknown> = {};
  if (data) d = data;
  const serializedSubspaceData = utf8ToBytes(JSON.stringify(subspaceData));
  const encSubspaceData = await encrypt(pubKeyBytes, serializedSubspaceData);
  const encSubspaceDataHex = encParamsBufToHex(encSubspaceData);
  d[subspace] = encSubspaceDataHex;
  await encryptAndSetData(m, webAuthnRefBytes, d, WEBAUTHN_TORUS_SHARE);
}

export async function setDeviceShare(m: MetadataStorageLayer, webAuthnRefBytes: Uint8Array, subspace: string, subspaceData: unknown): Promise<void> {
  const data = await getAndDecryptData(m, webAuthnRefBytes, WEBAUTHN_DEVICE_SHARE);
  let d: Record<string, unknown> = {};
  if (data) d = data;
  d[subspace] = subspaceData;
  await encryptAndSetData(m, webAuthnRefBytes, d, WEBAUTHN_DEVICE_SHARE);
}

export async function getTorusShare<T>(
  m: MetadataStorageLayer,
  webAuthnKeyBytes: Uint8Array,
  webAuthnRefBytes: Uint8Array,
  subspace: string
): Promise<T | null> {
  const data = await getAndDecryptData<EciesHex>(m, webAuthnRefBytes, WEBAUTHN_TORUS_SHARE);
  if (!data) return null;
  const encParamsHex = data[subspace];
  if (!encParamsHex) return null;
  const encParams = encParamsHexToBuf(encParamsHex);
  const privKeyBytes = webAuthnKeyBytes;
  const serializedBytes = await decrypt(privKeyBytes, encParams);
  const subspaceData = JSON.parse(bytesToUtf8(serializedBytes));
  return subspaceData;
}

export async function getDeviceShare<T>(m: MetadataStorageLayer, webAuthnRefBytes: Uint8Array, subspace: string): Promise<T | null> {
  const data = await getAndDecryptData<T>(m, webAuthnRefBytes, WEBAUTHN_DEVICE_SHARE);
  if (data) return data[subspace];
  return null;
}
