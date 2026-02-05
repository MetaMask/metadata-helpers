import { post, setAPIKey, setEmbedHost } from "@toruslabs/http-helpers";
import stringify from "json-stable-stringify";

import { bytesToBase64, getPublicKeyCoords, hexToBytes, keccak256, secp256k1, toEthereumSignature, utf8ToBytes } from "./utils";

export type PubKeyParams = {
  pub_key_X: string;
  pub_key_Y: string;
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

  generateMetadataParams(message: string, privateKeyHex: string): MetadataParams {
    const privKeyBytes = hexToBytes(privateKeyHex.padStart(64, "0"));
    const { x, y } = getPublicKeyCoords(privateKeyHex);
    const setData = {
      data: message,
      timestamp: Math.floor(this.serverTimeOffset + Date.now() / 1000).toString(16),
    };
    const msgHash = keccak256(utf8ToBytes(stringify(setData)));
    const sigBytes = secp256k1.sign(msgHash, privKeyBytes, { prehash: false, format: "recovered" });
    return {
      pub_key_X: x,
      pub_key_Y: y,
      set_data: setData,
      signature: bytesToBase64(toEthereumSignature(sigBytes)),
    };
  }

  generatePubKeyParams(privateKeyHex: string): PubKeyParams {
    const { x, y } = getPublicKeyCoords(privateKeyHex);
    return {
      pub_key_X: x,
      pub_key_Y: y,
    };
  }

  async setMetadata(data: MetadataParams, namespace: string | null, options?: RequestInit): Promise<string> {
    const params = namespace !== null ? { ...data, namespace } : data;
    const metadataResponse = await post<{ message: string }>(`${this.metadataHost}/set`, params, options, { useAPIKey: true });
    return metadataResponse.message;
  }

  async getMetadata(pubKey: PubKeyParams, namespace: string | null, options?: RequestInit): Promise<string> {
    const params = namespace !== null ? { ...pubKey, namespace } : pubKey;
    const metadataResponse = await post<{ message: string }>(`${this.metadataHost}/get`, params, options, { useAPIKey: true });
    return metadataResponse.message;
  }
}
