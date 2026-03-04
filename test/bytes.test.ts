import { describe, expect, it } from "vitest";

import {
  areUint8ArraysEqual,
  assertIsBytes,
  base64ToBytes,
  bigIntToBytes,
  bytesToBase64,
  bytesToBigInt,
  bytesToHexPrefixedString as bytesToHex,
  bytesToNumber,
  bytesToSignedBigInt,
  bytesToUtf8,
  concatBytes,
  hexToBytes,
  isBytes,
  numberToBytes,
  signedBigIntToBytes,
  utf8ToBytes,
  valueToBytes,
} from "../src/helpers/bytes";
import {
  BYTES_FIXTURES,
  INVALID_BYTES_FIXTURES,
  LARGE_BYTES_FIXTURES,
  TWOS_COMPLEMENT_BYTES_FIXTURES,
  UPPER_CASE_HEX_FIXTURES,
  UTF_8_BYTES_FIXTURES,
} from "./fixtures";

describe("isBytes", () => {
  it("returns true for a Uint8Array", () => {
    expect(isBytes(new Uint8Array())).toBe(true);
  });

  it.each(INVALID_BYTES_FIXTURES)("returns false for other values", (value) => {
    expect(isBytes(value)).toBe(false);
  });
});

describe("assertIsBytes", () => {
  it("does not throw for a Uint8Array", () => {
    expect(() => assertIsBytes(new Uint8Array())).not.toThrow();
  });

  it.each(INVALID_BYTES_FIXTURES)("throws for other values", (value) => {
    expect(() => assertIsBytes(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("bytesToHex", () => {
  it.each(BYTES_FIXTURES)("returns a hex string from a byte array", ({ bytes, hexadecimal }) => {
    expect(bytesToHex(bytes)).toBe(hexadecimal);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a hex string from a large byte array", ({ bytes, hexadecimal }) => {
    expect(bytesToHex(bytes)).toBe(hexadecimal);
  });

  it("adds a 0x-prefix to the string", () => {
    expect(bytesToHex(new Uint8Array([0, 1, 2])).startsWith("0x")).toBe(true);
  });

  it("returns 0x for an empty byte array", () => {
    expect(bytesToHex(new Uint8Array())).toBe("0x");
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error for invalid byte arrays", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bytesToHex(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("bytesToBigInt", () => {
  it.each(BYTES_FIXTURES)("returns a bigint from a byte array", ({ bytes, bigint }) => {
    expect(bytesToBigInt(bytes)).toBe(bigint);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a hex string from a large byte array", ({ bytes, bigint }) => {
    expect(bytesToBigInt(bytes)).toBe(bigint);
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error for invalid byte arrays", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bytesToBigInt(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("bytesToSignedBigInt", () => {
  it.each(TWOS_COMPLEMENT_BYTES_FIXTURES)("returns a signed bigint from a byte array", ({ bytes, bigint }) => {
    expect(bytesToSignedBigInt(bytes)).toBe(bigint);
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error for invalid byte arrays", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bytesToSignedBigInt(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("bytesToNumber", () => {
  it.each(BYTES_FIXTURES)("returns a number from a byte array", ({ bytes, number }) => {
    expect(bytesToNumber(bytes)).toBe(number);
  });

  it.each(LARGE_BYTES_FIXTURES)("throws an error when the resulting number is not a safe integer", ({ bytes }) => {
    expect(() => bytesToNumber(bytes)).toThrow("Number is not a safe integer. Use `bytesToBigInt` instead.");
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error for invalid byte arrays", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bytesToNumber(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("bytesToUtf8", () => {
  it.each(UTF_8_BYTES_FIXTURES)("returns a string from a byte array", ({ bytes, string }) => {
    expect(bytesToUtf8(bytes)).toBe(string);
  });
});

describe("bytesToBase64", () => {
  it.each(BYTES_FIXTURES)("returns a base64 string from a byte array", ({ bytes, base64 }) => {
    expect(bytesToBase64(bytes)).toBe(base64);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a base64 string from a large byte array", ({ bytes, base64 }) => {
    expect(bytesToBase64(bytes)).toBe(base64);
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error for invalid byte arrays", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bytesToBase64(value)).toThrow("Value must be a Uint8Array.");
  });
});

describe("hexToBytes", () => {
  it.each(BYTES_FIXTURES)("returns a byte array from a hex string", ({ bytes, hexadecimal }) => {
    expect(hexToBytes(hexadecimal)).toStrictEqual(bytes);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a byte array from a large hex string", ({ bytes, hexadecimal }) => {
    expect(hexToBytes(hexadecimal)).toStrictEqual(bytes);
  });

  it.each(UPPER_CASE_HEX_FIXTURES)("returns a byte array from an upper case hex string", ({ bytes, hexadecimal }) => {
    expect(hexToBytes(hexadecimal)).toStrictEqual(bytes);
  });

  it("supports a string with an odd length", () => {
    expect(hexToBytes("abc")).toStrictEqual(new Uint8Array([10, 188]));
  });

  it("returns an empty byte array for 0x", () => {
    expect(hexToBytes("0x")).toStrictEqual(new Uint8Array());
  });

  it.each([true, false, null, undefined, 0, 1, "", [], {}])("throws an error for invalid hex strings", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => hexToBytes(value)).toThrow("Value must be a hexadecimal string.");
  });
});

describe("bigIntToBytes", () => {
  it.each(BYTES_FIXTURES)("returns a byte array from a bigint", ({ bytes, bigint }) => {
    expect(bigIntToBytes(bigint)).toStrictEqual(bytes);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a byte array from a large bigint", ({ bytes, bigint }) => {
    expect(bigIntToBytes(bigint)).toStrictEqual(bytes);
  });

  it.each([true, false, null, undefined, 0, 1, "", "0x", [], {}])("throws an error for invalid bigints", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bigIntToBytes(value)).toThrow("Value must be a bigint.");
  });

  it("throws for negative bigints", () => {
    expect(() => bigIntToBytes(BigInt(-1))).toThrow("Value must be a non-negative bigint.");
  });
});

describe("signedBigIntToBytes", () => {
  it.each(TWOS_COMPLEMENT_BYTES_FIXTURES)("returns a byte array from a signed bigint", ({ bytes, bigint, length }) => {
    expect(signedBigIntToBytes(bigint, length)).toStrictEqual(bytes);
  });

  it.each([true, false, null, undefined, 0, 1, "", "0x", [], {}])("throws an error for invalid bigints", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => signedBigIntToBytes(value, 1)).toThrow("Value must be a bigint.");
  });

  it.each([true, false, null, undefined, "", "0x", [], {}])("throws an error for invalid lengths", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => signedBigIntToBytes(BigInt(1), value)).toThrow("Byte length must be a number.");
  });

  it("throws for byte lengths that are less than 1", () => {
    expect(() => signedBigIntToBytes(BigInt(1), 0)).toThrow("Byte length must be greater than 0.");
  });

  it.each([
    {
      bigint: BigInt(128),
      length: 1,
    },
    {
      bigint: BigInt(65536),
      length: 2,
    },
    {
      bigint: BigInt(2147483648),
      length: 4,
    },
    {
      bigint: BigInt(-129),
      length: 1,
    },
    {
      bigint: BigInt(-65537),
      length: 2,
    },
    {
      bigint: BigInt(-2147483649),
      length: 4,
    },
  ])("throws if the byte length is too small", ({ bigint, length }) => {
    expect(() => signedBigIntToBytes(bigint, length)).toThrow("Byte length is too small to represent the given value.");
  });
});

describe("numberToBytes", () => {
  it.each(BYTES_FIXTURES)("returns a byte array from a number", ({ bytes, number }) => {
    expect(numberToBytes(number)).toStrictEqual(bytes);
  });

  it.each(LARGE_BYTES_FIXTURES)("throws an error when the number is not a safe integer", ({ bigint }) => {
    expect(() => numberToBytes(Number(bigint))).toThrow("Value is not a safe integer. Use `bigIntToBytes` instead.");
  });

  it.each([true, false, null, undefined, BigInt(0), BigInt(1), "", "0x", [], {}])("throws an error for invalid numbers", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => numberToBytes(value)).toThrow("Value must be a number.");
  });

  it("throws for negative numbers", () => {
    expect(() => numberToBytes(-1)).toThrow("Value must be a non-negative number.");
  });
});

describe("utf8ToBytes", () => {
  it.each(UTF_8_BYTES_FIXTURES)("returns a byte array from a string", ({ bytes, string }) => {
    expect(utf8ToBytes(string)).toStrictEqual(bytes);
  });
});

describe("base64ToBytes", () => {
  it.each(BYTES_FIXTURES)("returns a byte array from a base64 string", ({ bytes, base64 }) => {
    expect(base64ToBytes(base64)).toStrictEqual(bytes);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a byte array from a large base64 string", ({ bytes, base64 }) => {
    expect(base64ToBytes(base64)).toStrictEqual(bytes);
  });

  it("decodes base64url strings with url-safe characters", () => {
    // "+" becomes "-" and "/" becomes "_" in base64url
    const standardBase64 = "/////w==";
    const base64url = "_____w";
    expect(base64ToBytes(base64url)).toStrictEqual(base64ToBytes(standardBase64));
  });

  it("decodes unpadded base64 strings", () => {
    // "AQ==" without padding is "AQ"
    expect(base64ToBytes("AQ")).toStrictEqual(new Uint8Array([1]));
    // "AQA=" without padding is "AQA"
    expect(base64ToBytes("AQA")).toStrictEqual(new Uint8Array([1, 0]));
  });

  it("decodes base64url with both url-safe chars and missing padding", () => {
    // Standard: "f//tog==" -> base64url: "f__tog"
    const expected = new Uint8Array([127, 255, 237, 162]);
    expect(base64ToBytes("f__tog")).toStrictEqual(expected);
    expect(base64ToBytes("f//tog==")).toStrictEqual(expected);
  });
});

describe("valueToBytes", () => {
  it.each(BYTES_FIXTURES)("returns a byte array from a value", ({ bigint, number, hexadecimal, bytes }) => {
    expect(valueToBytes(bigint)).toStrictEqual(bytes);
    expect(valueToBytes(number)).toStrictEqual(bytes);
    expect(valueToBytes(hexadecimal)).toStrictEqual(bytes);
    expect(valueToBytes(bytes)).toBe(bytes);
  });

  it.each(LARGE_BYTES_FIXTURES)("returns a byte array from a large value", ({ bigint, hexadecimal, bytes }) => {
    expect(valueToBytes(bigint)).toStrictEqual(bytes);
    expect(valueToBytes(hexadecimal)).toStrictEqual(bytes);
    expect(valueToBytes(bytes)).toBe(bytes);
  });

  it.each(UTF_8_BYTES_FIXTURES)("returns a byte array from a string", ({ bytes, string }) => {
    expect(valueToBytes(string)).toStrictEqual(bytes);
  });

  it.each(INVALID_BYTES_FIXTURES)("throws an error when the value cannot be converted to bytes", (value) => {
    // @ts-expect-error Invalid value.
    expect(() => valueToBytes(value)).toThrow(/Unsupported value type: ".+"\./u);
  });
});

describe("concatBytes", () => {
  it("returns a byte array from multiple byte arrays", () => {
    expect(concatBytes([new Uint8Array([1]), new Uint8Array([2])])).toStrictEqual(Uint8Array.from([1, 2]));
  });

  it("returns a byte array from multiple byte arrays and values", () => {
    expect(concatBytes([new Uint8Array([1]), 2, BigInt(3), "4", "0x5"])).toStrictEqual(Uint8Array.from([1, 2, 3, 52, 5]));
  });
});

describe("areUint8ArraysEqual", () => {
  it("returns true if the Uint8Arrays are equal", () => {
    expect(areUint8ArraysEqual(new Uint8Array(32).fill(1), new Uint8Array(32).fill(1))).toBe(true);
  });

  it("returns false if the Uint8Arrays are not equal", () => {
    expect(areUint8ArraysEqual(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2))).toBe(false);
  });

  it("returns false if the Uint8Arrays length is different", () => {
    expect(areUint8ArraysEqual(new Uint8Array(32).fill(1), new Uint8Array(31).fill(1))).toBe(false);
  });

  it("returns false if the first Uint8Array is shorter than the second", () => {
    expect(areUint8ArraysEqual(new Uint8Array(31).fill(1), new Uint8Array(32).fill(1))).toBe(false);
  });

  it("returns true if the Uint8Arrays are both empty", () => {
    expect(areUint8ArraysEqual(new Uint8Array(), new Uint8Array())).toBe(true);
  });

  it("returns false if there is a subtle difference in the Uint8Arrays", () => {
    expect(
      areUint8ArraysEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), new Uint8Array([1, 2, 3, 4, 5, 6, 2, 8, 9, 10, 11, 12]))
    ).toBe(false);
  });

  it("has similar runtime for early vs late differences on large arrays", () => {
    const LENGTH = 100_000;
    const ITERATIONS = 200;

    const base = new Uint8Array(LENGTH).fill(7);
    const early = base.slice();
    const late = base.slice();
    early[0] = 6; // first element differs
    late[LENGTH - 1] = 6; // last element differs

    // Warm up JIT
    for (let i = 0; i < 20; i++) {
      areUint8ArraysEqual(base, base);

      areUint8ArraysEqual(early, base);

      areUint8ArraysEqual(late, base);
    }

    const now = () => Number(Date.now());

    let earlyTotal = 0;
    let lateTotal = 0;

    // Measure early difference
    const startEarly = now();
    for (let i = 0; i < ITERATIONS; i++) {
      areUint8ArraysEqual(early, base);
    }
    earlyTotal = now() - startEarly;

    // Measure late difference
    const startLate = now();
    for (let i = 0; i < ITERATIONS; i++) {
      areUint8ArraysEqual(late, base);
    }
    lateTotal = now() - startLate;

    // Ratio ≈ 1.0 ⇒ similar runtimes regardless of diff position.
    // The threshold enforces the same order of magnitude while allowing normal system jitter.
    // It's an empirical upper bound (~p95). To tune: run multiple trials, take a high percentile, and set slightly above it.
    const ratio = earlyTotal > lateTotal ? earlyTotal / lateTotal : lateTotal / earlyTotal;
    expect(ratio).toBeLessThan(1.1);
  });
});
