import { decrypt, Ecies, encrypt, getPublic } from "@toruslabs/eccrypto";

import { MetadataStorageLayer, PubKeyParams } from "./MetadataStorageLayer";
import { bytesToHex, bytesToUtf8, coordsToPublicKey, getPublicKeyCoords, hexToBytes, utf8ToBytes } from "./utils";

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

export async function encryptData(privKeyHex: string, d: unknown): Promise<string> {
  const serializedData = utf8ToBytes(JSON.stringify(d));
  const privKeyBytes = hexToBytes(privKeyHex.padStart(64, "0"));
  const encParams = await encrypt(getPublic(privKeyBytes), serializedData);
  const encParamsHex = encParamsBufToHex(encParams);
  return JSON.stringify(encParamsHex);
}

export async function decryptData<T>(privKeyHex: string, d: string): Promise<T> {
  const encParamsHex: EciesHex = JSON.parse(d);
  const encParams = encParamsHexToBuf(encParamsHex);
  const privKeyBytes = hexToBytes(privKeyHex.padStart(64, "0"));
  const serializedBytes = await decrypt(privKeyBytes, encParams);
  const data: T = JSON.parse(bytesToUtf8(serializedBytes));
  return data;
}

export async function getAndDecryptData<T>(m: MetadataStorageLayer, privKeyHex: string, namespace: string): Promise<Record<string, T> | null> {
  const { x, y } = getPublicKeyCoords(privKeyHex);
  const serializedData = await m.getMetadata({ pub_key_X: x, pub_key_Y: y }, namespace);
  if (!serializedData) {
    return null;
  }
  const data = await decryptData<T>(privKeyHex, serializedData);
  return data as Record<string, T>;
}

export async function encryptAndSetData(m: MetadataStorageLayer, privKeyHex: string, d: Record<string, unknown>, namespace: string): Promise<void> {
  const sData = await encryptData(privKeyHex, d);
  const metadataParams = m.generateMetadataParams(sData, privKeyHex);
  await m.setMetadata(metadataParams, namespace);
}

export async function setTorusShare(
  m: MetadataStorageLayer,
  webAuthnPubKey: PubKeyParams,
  webAuthnRefHex: string,
  subspace: string,
  subspaceData: unknown
): Promise<void> {
  const pubKeyBytes = coordsToPublicKey(webAuthnPubKey.pub_key_X, webAuthnPubKey.pub_key_Y);
  const data = await getAndDecryptData(m, webAuthnRefHex, WEBAUTHN_TORUS_SHARE);
  let d: Record<string, unknown> = {};
  if (data) d = data;
  const serializedSubspaceData = utf8ToBytes(JSON.stringify(subspaceData));
  const encSubspaceData = await encrypt(pubKeyBytes, serializedSubspaceData);
  const encSubspaceDataHex = encParamsBufToHex(encSubspaceData);
  d[subspace] = encSubspaceDataHex;
  await encryptAndSetData(m, webAuthnRefHex, d, WEBAUTHN_TORUS_SHARE);
}

export async function setDeviceShare(m: MetadataStorageLayer, webAuthnRefHex: string, subspace: string, subspaceData: unknown): Promise<void> {
  const data = await getAndDecryptData(m, webAuthnRefHex, WEBAUTHN_DEVICE_SHARE);
  let d: Record<string, unknown> = {};
  if (data) d = data;
  d[subspace] = subspaceData;
  await encryptAndSetData(m, webAuthnRefHex, d, WEBAUTHN_DEVICE_SHARE);
}

export async function getTorusShare<T>(m: MetadataStorageLayer, webAuthnKeyHex: string, webAuthnRefHex: string, subspace: string): Promise<T | null> {
  const data = await getAndDecryptData<EciesHex>(m, webAuthnRefHex, WEBAUTHN_TORUS_SHARE);
  if (!data) return null;
  const encParamsHex = data[subspace];
  if (!encParamsHex) return null;
  const encParams = encParamsHexToBuf(encParamsHex);
  const privKeyBytes = hexToBytes(webAuthnKeyHex.padStart(64, "0"));
  const serializedBytes = await decrypt(privKeyBytes, encParams);
  const subspaceData = JSON.parse(bytesToUtf8(serializedBytes));
  return subspaceData;
}

export async function getDeviceShare<T>(m: MetadataStorageLayer, webAuthnRefHex: string, subspace: string): Promise<T | null> {
  const data = await getAndDecryptData<T>(m, webAuthnRefHex, WEBAUTHN_DEVICE_SHARE);
  if (data) return data[subspace];
  return null;
}
