import { keccak_256 } from "@noble/hashes/sha3.js";
import { generatePrivate } from "@toruslabs/eccrypto";
import { describe, expect, it } from "vitest";

import { bytesToHexPrefixedString as bytesToHex } from "../src";
import { getPublicKeyCoords, utf8ToBytes } from "../src/helpers/utils";
import { MetadataStorageLayer } from "../src/MetadataStorageLayer";
import { getDeviceShare, getTorusShare, setDeviceShare, setTorusShare } from "../src/webAuthnShareResolver";

const storage = new MetadataStorageLayer();

// Generate private keys and get their hex representations
const privKeyBytes = generatePrivate();
const pubKey = getPublicKeyCoords(privKeyBytes);

const privKeyBytes2 = generatePrivate();
const pubKey2 = getPublicKeyCoords(privKeyBytes2);

describe("Metadata", () => {
  let randomMessage: string;

  it("should get nothing by default", async () => {
    const res = await storage.getMetadata({ pub_key_X: pubKey.x, pub_key_Y: pubKey.y }, null);
    expect(res).toBe("");
  });

  it("should set and get", async () => {
    // Set metadata
    randomMessage = JSON.stringify({ message: bytesToHex(keccak_256(utf8ToBytes(Date.now().toString()))) });
    const params = storage.generateMetadataParams(randomMessage, privKeyBytes);
    await storage.setMetadata(params, "metadata-test");

    // Get and verify metadata
    const message = await storage.getMetadata(storage.generatePubKeyParams(privKeyBytes), "metadata-test");
    expect(message).toBe(randomMessage);
  });

  it("should set and get WebAuthn Torus Share", async () => {
    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, "google", "customTorusShare");
    const googleShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, "google");
    expect(googleShare).toBe("customTorusShare");
  });

  it("should set and get WebAuthn Device Share", async () => {
    let googleShare = await getDeviceShare<string>(storage, privKeyBytes, "google");
    expect(googleShare).toBeNull();

    await setDeviceShare(storage, privKeyBytes, "google", "customDeviceShare");
    googleShare = await getDeviceShare<string>(storage, privKeyBytes, "google");
    expect(googleShare).toBe("customDeviceShare");
  });

  it("should set and get multiple WebAuthn Torus Shares", async () => {
    const subspaces = ["facebook", "twitter", "github"];
    const shares = ["fbShare", "twitterShare", "githubShare"];

    // Set shares for multiple subspaces
    for (let i = 0; i < subspaces.length; i++) {
      await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspaces[i], shares[i]);
    }

    // Get and verify shares for each subspace
    for (let i = 0; i < subspaces.length; i++) {
      const retrievedShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, subspaces[i]);
      expect(retrievedShare).toBe(shares[i]);
    }
  });

  it("should handle non-existent WebAuthn Torus Share", async () => {
    const nonExistentShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, "nonexistent");
    expect(nonExistentShare).toBeNull();
  });

  it("should update existing WebAuthn Torus Share", async () => {
    const initialShare = "initialShare";
    const updatedShare = "updatedShare";
    const subspace = "updateTest";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspace, initialShare);

    let retrievedShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, subspace);
    expect(retrievedShare).toBe(initialShare);

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspace, updatedShare);

    retrievedShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, subspace);
    expect(retrievedShare).toBe(updatedShare);
  });

  it("should handle multiple subspaces with different data types", { timeout: 60000 }, async () => {
    const subspaces = ["stringSpace", "numberSpace", "objectSpace"];
    const shares = ["testString", 42, { key: "value" }];

    for (let i = 0; i < subspaces.length; i++) {
      await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspaces[i], shares[i]);
    }

    for (let i = 0; i < subspaces.length; i++) {
      const retrievedShare = await getTorusShare(storage, privKeyBytes2, privKeyBytes, subspaces[i]);
      expect(retrievedShare).toEqual(shares[i]);
    }
  });

  it("should handle empty string as share data", async () => {
    const emptyShare = "";
    const subspace = "emptySpace";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspace, emptyShare);

    const retrievedShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, subspace);
    expect(retrievedShare).toBe(emptyShare);
  });

  it("should handle large data in WebAuthn Torus Share", { timeout: 60000 }, async () => {
    const largeData = "x".repeat(1000000); // 1MB of data
    const subspace = "largeDataSpace";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyBytes, subspace, largeData);

    const retrievedShare = await getTorusShare<string>(storage, privKeyBytes2, privKeyBytes, subspace);
    expect(retrievedShare).toBe(largeData);
    expect(retrievedShare?.length).toBe(1000000);
  });
});
