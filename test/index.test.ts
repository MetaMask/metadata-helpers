import { generatePrivate } from "@toruslabs/eccrypto";
import { describe, expect, it } from "vitest";

import { MetadataStorageLayer } from "../src/MetadataStorageLayer";
import { bytesToHex, getPublicKeyCoords, keccak256, utf8ToBytes } from "../src/utils";
import { getDeviceShare, getTorusShare, setDeviceShare, setTorusShare } from "../src/webAuthnShareResolver";

const storage = new MetadataStorageLayer();

// Generate private keys and get their hex representations
const privKeyBytes = generatePrivate();
const privKeyHex = bytesToHex(privKeyBytes);
const pubKey = getPublicKeyCoords(privKeyHex);

const privKeyBytes2 = generatePrivate();
const privKeyHex2 = bytesToHex(privKeyBytes2);
const pubKey2 = getPublicKeyCoords(privKeyHex2);

describe("Metadata", () => {
  let randomMessage: string;

  it("should get nothing by default", async () => {
    const res = await storage.getMetadata({ pub_key_X: pubKey.x, pub_key_Y: pubKey.y }, null);
    expect(res).toBe("");
  });

  it("should set and get", async () => {
    // Set metadata
    randomMessage = JSON.stringify({ message: bytesToHex(keccak256(utf8ToBytes(Date.now().toString()))) });
    const params = storage.generateMetadataParams(randomMessage, privKeyHex);
    await storage.setMetadata(params, "metadata-test");

    // Get and verify metadata
    const message = await storage.getMetadata(storage.generatePubKeyParams(privKeyHex), "metadata-test");
    expect(message).toBe(randomMessage);
  });

  it("should set and get WebAuthn Torus Share", async () => {
    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, "google", "customTorusShare");
    const googleShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, "google");
    expect(googleShare).toBe("customTorusShare");
  });

  it("should set and get WebAuthn Device Share", async () => {
    let googleShare = await getDeviceShare<string>(storage, privKeyHex, "google");
    expect(googleShare).toBeNull();

    await setDeviceShare(storage, privKeyHex, "google", "customDeviceShare");
    googleShare = await getDeviceShare<string>(storage, privKeyHex, "google");
    expect(googleShare).toBe("customDeviceShare");
  });

  it("should set and get multiple WebAuthn Torus Shares", async () => {
    const subspaces = ["facebook", "twitter", "github"];
    const shares = ["fbShare", "twitterShare", "githubShare"];

    // Set shares for multiple subspaces
    for (let i = 0; i < subspaces.length; i++) {
      await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspaces[i], shares[i]);
    }

    // Get and verify shares for each subspace
    for (let i = 0; i < subspaces.length; i++) {
      const retrievedShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, subspaces[i]);
      expect(retrievedShare).toBe(shares[i]);
    }
  });

  it("should handle non-existent WebAuthn Torus Share", async () => {
    const nonExistentShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, "nonexistent");
    expect(nonExistentShare).toBeNull();
  });

  it("should update existing WebAuthn Torus Share", async () => {
    const initialShare = "initialShare";
    const updatedShare = "updatedShare";
    const subspace = "updateTest";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspace, initialShare);

    let retrievedShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, subspace);
    expect(retrievedShare).toBe(initialShare);

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspace, updatedShare);

    retrievedShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, subspace);
    expect(retrievedShare).toBe(updatedShare);
  });

  it("should handle multiple subspaces with different data types", { timeout: 60000 }, async () => {
    const subspaces = ["stringSpace", "numberSpace", "objectSpace"];
    const shares = ["testString", 42, { key: "value" }];

    for (let i = 0; i < subspaces.length; i++) {
      await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspaces[i], shares[i]);
    }

    for (let i = 0; i < subspaces.length; i++) {
      const retrievedShare = await getTorusShare(storage, privKeyHex2, privKeyHex, subspaces[i]);
      expect(retrievedShare).toEqual(shares[i]);
    }
  });

  it("should handle empty string as share data", async () => {
    const emptyShare = "";
    const subspace = "emptySpace";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspace, emptyShare);

    const retrievedShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, subspace);
    expect(retrievedShare).toBe(emptyShare);
  });

  it("should handle large data in WebAuthn Torus Share", { timeout: 60000 }, async () => {
    const largeData = "x".repeat(1000000); // 1MB of data
    const subspace = "largeDataSpace";

    await setTorusShare(storage, { pub_key_X: pubKey2.x, pub_key_Y: pubKey2.y }, privKeyHex, subspace, largeData);

    const retrievedShare = await getTorusShare<string>(storage, privKeyHex2, privKeyHex, subspace);
    expect(retrievedShare).toBe(largeData);
    expect(retrievedShare?.length).toBe(1000000);
  });
});
