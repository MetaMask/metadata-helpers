import { mod } from "@noble/curves/abstract/modular.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, it } from "vitest";

import { generateRandomPolynomial, lagrangeInterpolatePolynomial, lagrangeInterpolation, Point, Polynomial, Share } from "../src/helpers/lagrange";

const N = secp256k1.Point.CURVE().n;

describe("Point", () => {
  it("constructs with x, y, keyType", () => {
    const p = new Point(1n, 2n, "secp256k1");
    expect(p.x).toBe(1n);
    expect(p.y).toBe(2n);
    expect(p.keyType).toBe("secp256k1");
  });

  it("encodes as arr (uncompressed)", () => {
    const p = new Point(1n, 2n, "secp256k1");
    const encoded = p.encode("arr");
    expect(encoded[0]).toBe(0x04);
    expect(encoded.length).toBe(65);
  });

  it("throws for unknown encoding", () => {
    const p = new Point(1n, 2n, "secp256k1");
    expect(() => p.encode("unknown")).toThrow("encoding doesn't exist in Point");
  });
});

describe("Share", () => {
  it("round-trips via toJSON / fromJSON", () => {
    const s = new Share(3n, 42n);
    const json = s.toJSON();
    const restored = Share.fromJSON(json);
    expect(restored.shareIndex).toBe(3n);
    expect(restored.share).toBe(42n);
  });
});

describe("Polynomial", () => {
  it("evaluates a linear polynomial at x=1", () => {
    // f(x) = 5 + 3x mod N
    const poly = new Polynomial([5n, 3n], secp256k1);
    expect(poly.polyEval(1n)).toBe(mod(8n, N));
  });

  it("returns correct threshold", () => {
    const poly = new Polynomial([1n, 2n, 3n], secp256k1);
    expect(poly.getThreshold()).toBe(3);
  });

  it("generates shares for given indices", () => {
    const poly = new Polynomial([5n, 3n], secp256k1);
    const shares = poly.generateShares([1n, 2n, 3n]);
    const keys = Object.keys(shares);
    expect(keys.length).toBe(3);
  });
});

describe("lagrangeInterpolation", () => {
  it("recovers secret from 2-of-3 shares (linear polynomial)", () => {
    // f(x) = secret + coeff*x
    const secret = 12345n;
    const coeff = 67890n;
    const shares = [1n, 2n, 3n].map((x) => mod(secret + coeff * x, N));
    const nodeIndex = [1n, 2n, 3n];

    // Use only 2 shares (threshold = 2 for degree-1 polynomial)
    const recovered = lagrangeInterpolation(secp256k1, shares.slice(0, 2), nodeIndex.slice(0, 2));
    expect(recovered).toBe(mod(secret, N));
  });

  it("throws if shares and nodeIndex have different lengths", () => {
    expect(() => lagrangeInterpolation(secp256k1, [1n, 2n], [1n])).toThrow("shares not equal to nodeIndex length");
  });
});

describe("lagrangeInterpolatePolynomial", () => {
  it("interpolates points back into polynomial", () => {
    const secret = 100n;
    const coeff = 200n;
    const points = [1n, 2n].map((x) => new Point(x, mod(secret + coeff * x, N), "secp256k1"));

    const poly = lagrangeInterpolatePolynomial(secp256k1, points);
    expect(poly.polyEval(0n)).toBe(mod(secret, N));
  });
});

describe("generateRandomPolynomial", () => {
  it("generates polynomial with correct degree", () => {
    const poly = generateRandomPolynomial(secp256k1, "secp256k1", 2);
    expect(poly.getThreshold()).toBe(3); // degree + 1
  });

  it("uses provided secret as constant term", () => {
    const secret = 42n;
    const poly = generateRandomPolynomial(secp256k1, "secp256k1", 2, secret);
    expect(poly.polyEval(0n)).toBe(secret);
  });

  it("generates shares that can reconstruct the secret", () => {
    const secret = 999n;
    const degree = 2;
    const poly = generateRandomPolynomial(secp256k1, "secp256k1", degree, secret);

    const indices = [1n, 2n, 3n];
    const shares = indices.map((i) => poly.polyEval(i));

    const recovered = lagrangeInterpolation(secp256k1, shares, indices);
    expect(recovered).toBe(mod(secret, N));
  });

  it("works with deterministic shares", () => {
    const secret = 42n;
    const deterministicShare = new Share(1n, 100n);
    const poly = generateRandomPolynomial(secp256k1, "secp256k1", 2, secret, [deterministicShare]);
    expect(poly.polyEval(0n)).toBe(secret);
    expect(poly.polyEval(1n)).toBe(100n);
  });

  it("throws if deterministic shares exceed degree", () => {
    const s1 = new Share(1n, 10n);
    const s2 = new Share(2n, 20n);
    const s3 = new Share(3n, 30n);
    expect(() => generateRandomPolynomial(secp256k1, "secp256k1", 2, 42n, [s1, s2, s3])).toThrow(
      "deterministicShares in generateRandomPolynomial should be less or equal than degree"
    );
  });
});
