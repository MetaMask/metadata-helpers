import { invert, mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberBE, concatBytes, hexToBytes, numberToBytesBE } from "@noble/curves/utils.js";

import type { Curve, KeyType } from "./crypto";
import { generatePrivateKey, getSecp256k1 } from "./crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type StringifiedType = Record<string, unknown>;

export type ShareJSON = { share: string; shareIndex: string };

export type ShareMap = { [x: string]: Share };

// ---------------------------------------------------------------------------
// Helper: bigint ↔ hex (local to avoid circular dependency with number.ts)
// ---------------------------------------------------------------------------

function bigintToHex(val: bigint, padLength = 64): string {
  return val.toString(16).padStart(padLength, "0");
}

function hexToBigIntLocal(val: string): bigint {
  const cleaned = val.replace(/^0x/, "");
  if (!cleaned) return 0n;
  return BigInt(`0x${cleaned}`);
}

// ---------------------------------------------------------------------------
// Point
// ---------------------------------------------------------------------------

export class Point {
  x: bigint;
  y: bigint;
  keyType: KeyType;

  constructor(x: bigint, y: bigint, keyType: KeyType) {
    this.x = x;
    this.y = y;
    this.keyType = keyType;
  }

  encode(enc: string): Uint8Array {
    switch (enc) {
      case "arr":
        return concatBytes(hexToBytes("04"), numberToBytesBE(this.x, 32), numberToBytesBE(this.y, 32));
      case "elliptic-compressed": {
        if (this.keyType === "secp256k1") {
          const point = getSecp256k1().Point.fromAffine({ x: this.x, y: this.y });
          return point.toBytes();
        }
        const point = ed25519.Point.fromAffine({ x: this.x, y: this.y });
        return point.toBytes();
      }
      default:
        throw new Error("encoding doesn't exist in Point");
    }
  }
}

// ---------------------------------------------------------------------------
// Share
// ---------------------------------------------------------------------------

export class Share {
  share: bigint;
  shareIndex: bigint;

  constructor(shareIndex: bigint, share: bigint) {
    this.share = share;
    this.shareIndex = shareIndex;
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value as ShareJSON;
    return new Share(hexToBigIntLocal(shareIndex), hexToBigIntLocal(share));
  }

  toJSON(): ShareJSON {
    return {
      share: bigintToHex(this.share),
      shareIndex: bigintToHex(this.shareIndex),
    };
  }
}

// ---------------------------------------------------------------------------
// Polynomial
// ---------------------------------------------------------------------------

export class Polynomial {
  polynomial: bigint[];
  ecCurve: Curve;

  constructor(polynomial: bigint[], ecCurve: Curve) {
    this.polynomial = polynomial;
    this.ecCurve = ecCurve;
  }

  getThreshold(): number {
    return this.polynomial.length;
  }

  polyEval(x: bigint): bigint {
    const n = this.ecCurve.Point.CURVE().n;
    let xi = x;
    let sum = this.polynomial[0]!;
    for (let i = 1; i < this.polynomial.length; i += 1) {
      const tmp = xi * this.polynomial[i]!;
      sum = mod(sum + tmp, n);
      xi = mod(xi * x, n);
    }
    return sum;
  }

  generateShares(shareIndexes: bigint[]): ShareMap {
    const shares: ShareMap = {};
    for (let x = 0; x < shareIndexes.length; x += 1) {
      const idx = shareIndexes[x]!;
      shares[bigintToHex(idx)] = new Share(idx, this.polyEval(idx));
    }
    return shares;
  }
}

// ---------------------------------------------------------------------------
// Lagrange interpolation
// ---------------------------------------------------------------------------

function generatePrivateExcludingIndexes(shareIndexes: bigint[], keyType: KeyType): bigint {
  const key = bytesToNumberBE(generatePrivateKey(keyType));
  if (shareIndexes.find((el) => el === key)) {
    return generatePrivateExcludingIndexes(shareIndexes, keyType);
  }
  return key;
}

const generateEmptyBigIntArray = (length: number): bigint[] => Array.from({ length }, () => 0n);

const denominator = (ecCurve: Curve, i: number, innerPoints: Point[]) => {
  const n = ecCurve.Point.CURVE().n;
  let result = 1n;
  const xi = innerPoints[i]!.x;
  for (let j = innerPoints.length - 1; j >= 0; j -= 1) {
    if (i !== j) {
      let tmp = xi - innerPoints[j]!.x;
      tmp = mod(tmp, n);
      result = mod(result * tmp, n);
    }
  }
  return result;
};

const interpolationPoly = (ecCurve: Curve, i: number, innerPoints: Point[]): bigint[] => {
  const n = ecCurve.Point.CURVE().n;
  let coefficients = generateEmptyBigIntArray(innerPoints.length);
  const d = denominator(ecCurve, i, innerPoints);
  if (d === 0n) {
    throw new Error("Denominator for interpolationPoly is 0");
  }
  coefficients[0] = invert(d, n);
  for (let k = 0; k < innerPoints.length; k += 1) {
    const newCoefficients = generateEmptyBigIntArray(innerPoints.length);
    if (k !== i) {
      let j: number;
      if (k < i) {
        j = k + 1;
      } else {
        j = k;
      }
      j -= 1;
      for (; j >= 0; j -= 1) {
        newCoefficients[j + 1] = mod(newCoefficients[j + 1]! + coefficients[j]!, n);
        const tmp = mod(innerPoints[k]!.x * coefficients[j]!, n);
        newCoefficients[j] = mod(newCoefficients[j]! - tmp, n);
      }
      coefficients = newCoefficients;
    }
  }
  return coefficients;
};

const pointSort = (innerPoints: Point[]): Point[] => {
  const pointArrClone = [...innerPoints];
  pointArrClone.sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : 0));
  return pointArrClone;
};

const lagrange = (ecCurve: Curve, unsortedPoints: Point[]) => {
  const n = ecCurve.Point.CURVE().n;
  const sortedPoints = pointSort(unsortedPoints);
  const polynomial = generateEmptyBigIntArray(sortedPoints.length);
  for (let i = 0; i < sortedPoints.length; i += 1) {
    const coefficients = interpolationPoly(ecCurve, i, sortedPoints);
    for (let k = 0; k < sortedPoints.length; k += 1) {
      const tmp = sortedPoints[i]!.y * coefficients[k]!;
      polynomial[k] = mod(polynomial[k]! + tmp, n);
    }
  }
  return new Polynomial(polynomial, ecCurve);
};

export function lagrangeInterpolatePolynomial(ecCurve: Curve, points: Point[]): Polynomial {
  return lagrange(ecCurve, points);
}

export function lagrangeInterpolation(ecCurve: Curve, shares: bigint[], nodeIndex: bigint[]): bigint {
  if (shares.length !== nodeIndex.length) {
    throw new Error("shares not equal to nodeIndex length in lagrangeInterpolation");
  }
  const n = ecCurve.Point.CURVE().n;
  let secret = 0n;
  for (let i = 0; i < shares.length; i += 1) {
    let upper = 1n;
    let lower = 1n;
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = mod(upper * -nodeIndex[j]!, n);
        let temp = nodeIndex[i]! - nodeIndex[j]!;
        temp = mod(temp, n);
        lower = mod(lower * temp, n);
      }
    }
    let delta = mod(upper * invert(lower, n), n);
    delta = mod(delta * shares[i]!, n);
    secret = secret + delta;
  }
  return mod(secret, n);
}

/** Generate a random polynomial for Shamir's Secret Sharing. */
export function generateRandomPolynomial(
  ecCurve: Curve,
  keyType: KeyType,
  degree: number,
  secret?: bigint,
  deterministicShares?: Share[]
): Polynomial {
  const actualS = secret !== undefined ? secret : generatePrivateExcludingIndexes([0n], keyType);
  if (!deterministicShares) {
    const poly: bigint[] = [actualS];
    for (let i = 0; i < degree; i += 1) {
      const share = generatePrivateExcludingIndexes(poly, keyType);
      poly.push(share);
    }
    return new Polynomial(poly, ecCurve);
  }
  if (!Array.isArray(deterministicShares)) {
    throw new Error("deterministic shares in generateRandomPolynomial should be an array");
  }

  if (deterministicShares.length > degree) {
    throw new Error("deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
  }
  const points: Record<string, Point> = {};
  deterministicShares.forEach((share) => {
    points[bigintToHex(share.shareIndex)] = new Point(share.shareIndex, share.share, keyType);
  });
  for (let i = 0; i < degree - deterministicShares.length; i += 1) {
    let shareIndex = generatePrivateExcludingIndexes([0n], keyType);
    while (points[bigintToHex(shareIndex)] !== undefined) {
      shareIndex = generatePrivateExcludingIndexes([0n], keyType);
    }
    points[bigintToHex(shareIndex)] = new Point(shareIndex, bytesToNumberBE(generatePrivateKey(keyType)), keyType);
  }
  points["0"] = new Point(0n, actualS, keyType);
  return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
}
