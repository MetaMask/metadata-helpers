import { assert } from "./assert";
import { add0x, assertIsHexString } from "./hex";

export type HexOutputOptions = {
  /** When true (default), prepend "0x" to the result. Set false for raw hex. */
  prefixed?: boolean;
};

/**
 * Convert a number to a hexadecimal string. This verifies that the number is a
 * non-negative safe integer.
 *
 * To convert a `bigint` to a hexadecimal string instead, use
 * {@link bigIntToHexPrefixedString}.
 *
 * @example
 * ```typescript
 * numberToHexPrefixedString(16); // '0x10'
 * numberToHexPrefixedString(16, { prefixed: false }); // '10'
 * ```
 * @param value - The number to convert to a hexadecimal string.
 * @param options - Optional. Set `{ prefixed: false }` to omit the "0x" prefix.
 * @returns The hexadecimal string.
 * @throws If the number is not a non-negative safe integer.
 */
export const numberToHexPrefixedString = (value: number, options?: HexOutputOptions): string => {
  assert(typeof value === "number", "Value must be a number.");
  assert(value >= 0, "Value must be a non-negative number.");
  assert(Number.isSafeInteger(value), "Value is not a safe integer. Use `bigIntToHex` instead.");

  const hex = value.toString(16);
  return options?.prefixed === false ? hex : add0x(hex);
};

/**
 * Convert a `bigint` to a hexadecimal string. This verifies that the `bigint`
 * is a non-negative integer.
 *
 * To convert a number to a hexadecimal string instead, use {@link numberToHexPrefixedString}.
 *
 * @example
 * ```typescript
 * bigIntToHexPrefixedString(16n); // '0x10'
 * bigIntToHexPrefixedString(16n, { prefixed: false }); // '10'
 * ```
 * @param value - The `bigint` to convert to a hexadecimal string.
 * @param options - Optional. Set `{ prefixed: false }` to omit the "0x" prefix.
 * @returns The hexadecimal string.
 * @throws If the `bigint` is not a non-negative integer.
 */
export const bigIntToHexPrefixedString = (value: bigint, options?: HexOutputOptions): string => {
  assert(typeof value === "bigint", "Value must be a bigint.");
  assert(value >= 0, "Value must be a non-negative bigint.");

  const hex = value.toString(16);
  return options?.prefixed === false ? hex : add0x(hex);
};

/**
 * Convert a `bigint` to a zero-padded hexadecimal string (torus.js–compatible name).
 * By default returns without "0x" prefix.
 *
 * @example
 * ```typescript
 * bigintToHex(255n); // '00000...00ff' (64 chars, no prefix)
 * bigintToHex(255n, 4, { prefixed: true }); // '0x00ff'
 * ```
 * @param value - The bigint to convert.
 * @param length - Pad to this many hex characters (default 64).
 * @param options - Optional. Set `{ prefixed: true }` to add "0x" prefix.
 * @returns The padded hexadecimal string.
 */
export const bigintToHex = (value: bigint, length: number = 64, options?: HexOutputOptions): string => {
  let hex = value.toString(16).padStart(length, "0");
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  return options?.prefixed ? add0x(hex) : hex;
};

/** @deprecated Use bigintToHex. Kept for backward compatibility. */
export const bigIntToHexPaddedString = bigintToHex;

/**
 * Convert a hexadecimal string to a number. This verifies that the string is a
 * valid hex string, and that the resulting number is a safe integer. Both
 * "0x"-prefixed and unprefixed strings are supported.
 *
 * To convert a hexadecimal string to a `bigint` instead, use
 * {@link hexToBigInt}.
 *
 * @example
 * ```typescript
 * hexToNumber('0x0'); // 0
 * hexToNumber('0x1'); // 1
 * hexToNumber('0x10'); // 16
 * ```
 * @param value - The hexadecimal string to convert to a number.
 * @returns The number.
 * @throws If the value is not a valid hexadecimal string, or if the resulting
 * number is not a safe integer.
 */
export const hexToNumber = (value: string): number => {
  assertIsHexString(value);

  // `parseInt` accepts values without the "0x"-prefix, whereas `Number` does
  // not. Using this is slightly faster than `Number(add0x(value))`.
  const numberValue = parseInt(value, 16);

  assert(Number.isSafeInteger(numberValue), "Value is not a safe integer. Use `hexToBigInt` instead.");

  return numberValue;
};

/**
 * Convert a hexadecimal string to a `bigint`. This verifies that the string is
 * a valid hex string. Both "0x"-prefixed and unprefixed strings are supported.
 *
 * To convert a hexadecimal string to a number instead, use {@link hexToNumber}.
 *
 * @example
 * ```typescript
 * hexToBigInt('0x0'); // 0n
 * hexToBigInt('0x1'); // 1n
 * hexToBigInt('0x10'); // 16n
 * ```
 * @param value - The hexadecimal string to convert to a `bigint`.
 * @returns The `bigint`.
 * @throws If the value is not a valid hexadecimal string.
 */
export const hexToBigInt = (value: string): bigint => {
  assertIsHexString(value);

  // The `BigInt` constructor requires the "0x"-prefix to parse a hex string.
  return BigInt(add0x(value));
};

/**
 * Convert a hex string (with or without 0x prefix) or bigint to bigint.
 * Returns 0n for empty strings. Useful when parsing node responses where
 * values may be missing or empty.
 *
 * @param val - The hex string or bigint to convert.
 * @returns The bigint value.
 */
export const toBigIntBE = (val: string | bigint): bigint => {
  if (typeof val === "bigint") return val;
  const cleaned = val.replace(/^0x/, "");
  if (!cleaned) return 0n;
  return hexToBigInt(cleaned);
};
