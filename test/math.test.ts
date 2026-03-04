import { describe, expect, it } from "vitest";

import { calculateMedian, kCombinations, thresholdSame } from "../src/helpers/math";

describe("thresholdSame", () => {
  it("returns element that appears t times", () => {
    expect(thresholdSame([1, 2, 1, 3, 1], 3)).toBe(1);
  });

  it("returns undefined if no element meets threshold", () => {
    expect(thresholdSame([1, 2, 3, 4, 5], 2)).toBeUndefined();
  });

  it("works with objects (deep equality via json-stable-stringify)", () => {
    const a = { x: 1, y: 2 };
    const b = { y: 2, x: 1 };
    const c = { x: 3, y: 4 };
    expect(thresholdSame([a, b, c], 2)).toEqual({ x: 1, y: 2 });
  });

  it("returns the first element to reach threshold", () => {
    expect(thresholdSame(["a", "b", "a", "b", "a"], 2)).toBe("a");
  });

  it("handles empty array", () => {
    expect(thresholdSame([], 1)).toBeUndefined();
  });

  it("handles threshold of 1", () => {
    expect(thresholdSame([42], 1)).toBe(42);
  });

  it("works with null/undefined elements", () => {
    expect(thresholdSame([null, null, 1], 2)).toBeNull();
    expect(thresholdSame([undefined, undefined], 2)).toBeUndefined();
  });
});

describe("kCombinations", () => {
  it("generates all 2-combinations of [0,1,2]", () => {
    const result = kCombinations([0, 1, 2], 2);
    expect(result).toEqual([
      [0, 1],
      [0, 2],
      [1, 2],
    ]);
  });

  it("accepts a number as shorthand for range", () => {
    const result = kCombinations(3, 2);
    expect(result).toEqual([
      [0, 1],
      [0, 2],
      [1, 2],
    ]);
  });

  it("returns [set] when k === set.length", () => {
    expect(kCombinations([1, 2, 3], 3)).toEqual([[1, 2, 3]]);
  });

  it("returns singletons when k === 1", () => {
    expect(kCombinations([5, 6, 7], 1)).toEqual([[5], [6], [7]]);
  });

  it("returns empty array when k > set length", () => {
    expect(kCombinations([1, 2], 3)).toEqual([]);
  });

  it("returns empty array when k <= 0", () => {
    expect(kCombinations([1, 2, 3], 0)).toEqual([]);
    expect(kCombinations([1, 2, 3], -1)).toEqual([]);
  });

  it("generates correct count: C(5,3) = 10", () => {
    const result = kCombinations(5, 3);
    expect(result.length).toBe(10);
  });
});

describe("calculateMedian", () => {
  it("returns 0 for empty array", () => {
    expect(calculateMedian([])).toBe(0);
  });

  it("returns the middle element for odd-length array", () => {
    expect(calculateMedian([3, 1, 2])).toBe(2);
  });

  it("returns the average of two middle elements for even-length array", () => {
    expect(calculateMedian([1, 2, 3, 4])).toBe(2.5);
  });

  it("handles single element", () => {
    expect(calculateMedian([42])).toBe(42);
  });

  it("handles two elements", () => {
    expect(calculateMedian([10, 20])).toBe(15);
  });

  it("does not mutate the original array", () => {
    const arr = [3, 1, 2];
    const copy = [...arr];
    calculateMedian(arr);
    expect(arr).toEqual(copy);
  });
});
