import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { post, setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import stringify from "json-stable-stringify";

import { bytesToBase64, utf8ToBytes } from "./helpers/bytes";
import { bytesToHex, getPublicKeyCoords, toEthereumSignature } from "./helpers/utils";

export type PubKeyParams = {
  pub_key_X: Uint8Array;
  pub_key_Y: Uint8Array;
};

export type MetadataParams = PubKeyParams & {
  set_data: {
    data: string;
    timestamp: string;
  };
  signature: string;
};

export class MetadataStorageLayer {
  public metadataHost: string;

  public serverTimeOffset: number; // ms

  constructor(metadataHost = "https://metadata.tor.us", serverTimeOffset = 0) {
    this.metadataHost = metadataHost;
    this.serverTimeOffset = serverTimeOffset;
  }

  static setAPIKey(apiKey: string): void {
    setAPIKey(apiKey);
  }

  static setEmbedHost(embedHost: string): void {
    setEmbedHost(embedHost);
  }

  generateMetadataParams(message: string, privateKeyBytes: Uint8Array): MetadataParams {
    const { x, y } = getPublicKeyCoords(privateKeyBytes);
    const setData = {
      data: message,
      timestamp: Math.floor(this.serverTimeOffset + Date.now() / 1000).toString(16),
    };
    const msgHash = keccak_256(utf8ToBytes(stringify(setData)));
    const sigBytes = secp256k1.sign(msgHash, privateKeyBytes, { prehash: false, format: "recovered", lowS: false });
    return {
      pub_key_X: x,
      pub_key_Y: y,
      set_data: setData,
      signature: bytesToBase64(toEthereumSignature(sigBytes)),
    };
  }

  generatePubKeyParams(privateKeyBytes: Uint8Array): PubKeyParams {
    const { x, y } = getPublicKeyCoords(privateKeyBytes);
    return {
      pub_key_X: x,
      pub_key_Y: y,
    };
  }

  async setMetadata(data: MetadataParams, namespace: string | null, options?: RequestInit): Promise<string> {
    const pubKeyHex = {
      pub_key_X: bytesToHex(data.pub_key_X),
      pub_key_Y: bytesToHex(data.pub_key_Y),
    };
    const params = namespace !== null ? { ...data, ...pubKeyHex, namespace } : { ...data, ...pubKeyHex };
    const metadataResponse = await post<{ message: string }>(`${this.metadataHost}/set`, params, options, { useAPIKey: true });
    return metadataResponse.message;
  }

  async getMetadata(pubKey: PubKeyParams, namespace: string | null, options?: RequestInit): Promise<string> {
    const pubKeyHex = {
      pub_key_X: bytesToHex(pubKey.pub_key_X),
      pub_key_Y: bytesToHex(pubKey.pub_key_Y),
    };
    const params = namespace !== null ? { ...pubKeyHex, namespace } : pubKeyHex;
    const metadataResponse = await post<{ message: string }>(`${this.metadataHost}/get`, params, options, { useAPIKey: true });
    return metadataResponse.message;
  }
}
