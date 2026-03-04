import { describe, expect, it } from "vitest";

import {
  bigIntToHexPaddedString,
  bigIntToHexPrefixedString as bigIntToHex,
  hexToBigInt,
  hexToNumber,
  numberToHexPrefixedString as numberToHex,
  toBigIntBE,
} from "../src/helpers/number";
import { NUMBER_VALUES } from "./fixtures";

describe("numberToHex", () => {
  it.each(NUMBER_VALUES)("converts a number to a hex string", ({ number, hexadecimal }) => {
    expect(numberToHex(number)).toBe(hexadecimal);
  });

  it.each([true, false, null, undefined, {}, [], "", "0x", "0x0", BigInt(1)])("throws if the value is not a number", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => numberToHex(value)).toThrow("Value must be a number.");
  });

  it.each([-1, -1e100, -Infinity, NaN])("throws if the value is negative", (value) => {
    expect(() => numberToHex(value)).toThrow("Value must be a non-negative number.");
  });

  it.each([1.1, 1e100, Infinity])("throws if the value is not a safe integer", (value) => {
    expect(() => numberToHex(value)).toThrow("Value is not a safe integer. Use `bigIntToHex` instead.");
  });
});

describe("bigIntToHex", () => {
  it.each(NUMBER_VALUES)("converts a bigint to a hex string", ({ bigint, hexadecimal }) => {
    expect(bigIntToHex(bigint)).toBe(hexadecimal);
  });

  it.each([true, false, null, undefined, {}, [], "", "0x", "0x0", 1])("throws if the value is not a bigint", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => bigIntToHex(value)).toThrow("Value must be a bigint.");
  });

  it.each([BigInt(-1), BigInt("-100")])("throws if the value is negative", (value) => {
    expect(() => bigIntToHex(value)).toThrow("Value must be a non-negative bigint.");
  });
});

describe("hexToNumber", () => {
  it.each(NUMBER_VALUES)("converts a hex string to a number", ({ number, hexadecimal }) => {
    expect(hexToNumber(hexadecimal)).toBe(number);
  });

  it.each([true, false, null, undefined, 0, 1, "", [], {}, BigInt(1)])("throws if the value is not a hexadecimal string", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => hexToNumber(value)).toThrow("Value must be a hexadecimal string.");
  });
});

describe("hexToBigInt", () => {
  it.each(NUMBER_VALUES)("converts a hex string to a bigint", ({ bigint, hexadecimal }) => {
    expect(hexToBigInt(hexadecimal)).toBe(bigint);
  });

  it.each([true, false, null, undefined, 0, 1, "", [], {}, BigInt(1)])("throws if the value is not a hexadecimal string", (value) => {
    // @ts-expect-error Invalid type.
    expect(() => hexToBigInt(value)).toThrow("Value must be a hexadecimal string.");
  });
});

describe("prefixed option", () => {
  it("numberToHex: defaults to 0x-prefixed", () => {
    expect(numberToHex(16)).toBe("0x10");
  });

  it("numberToHex: { prefixed: false } strips 0x", () => {
    expect(numberToHex(16, { prefixed: false })).toBe("10");
  });

  it("bigIntToHex: defaults to 0x-prefixed", () => {
    expect(bigIntToHex(16n)).toBe("0x10");
  });

  it("bigIntToHex: { prefixed: false } strips 0x", () => {
    expect(bigIntToHex(16n, { prefixed: false })).toBe("10");
  });

  it("bigIntToHexPaddedString: defaults to no prefix", () => {
    const result = bigIntToHexPaddedString(255n, 4);
    expect(result).toBe("00ff");
  });

  it("bigIntToHexPaddedString: { prefixed: true } adds 0x", () => {
    expect(bigIntToHexPaddedString(255n, 4, { prefixed: true })).toBe("0x00ff");
  });
});

describe("toBigIntBE", () => {
  it("converts hex string without 0x prefix", () => {
    expect(toBigIntBE("ff")).toBe(255n);
  });

  it("converts hex string with 0x prefix", () => {
    expect(toBigIntBE("0xff")).toBe(255n);
  });

  it("passes through bigint unchanged", () => {
    expect(toBigIntBE(42n)).toBe(42n);
  });

  it("returns 0n for empty string", () => {
    expect(toBigIntBE("")).toBe(0n);
  });

  it("returns 0n for bare 0x", () => {
    expect(toBigIntBE("0x")).toBe(0n);
  });
});
