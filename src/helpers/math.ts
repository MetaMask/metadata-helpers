import stringify from "json-stable-stringify";

/**
 * Return the element that appears at least `t` times in `arr`,
 * or undefined if no element meets the threshold.
 * Comparison uses JSON-stable-stringify for deep equality.
 */
export const thresholdSame = <T>(arr: T[], t: number): T | undefined => {
  const hashMap: Record<string, number> = {};
  for (let i = 0; i < arr.length; i += 1) {
    const str = stringify(arr[i]);
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return arr[i];
    }
  }
  return undefined;
};

/**
 * Generate all k-combinations of a set.
 * @param s - Array of numbers, or a number n (shorthand for [0..n-1]).
 * @param k - Size of each combination.
 */
export const kCombinations = (s: number | number[], k: number): number[][] => {
  let set = s;
  if (typeof set === "number") {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return [];
  }

  if (k === set.length) {
    return [set];
  }

  if (k === 1) {
    return set.reduce((acc, cur) => [...acc, [cur]], [] as number[][]);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i]!, ...tailCombs[j]!]);
    }
  }

  return combs;
};

/**
 * Calculate the median of a numeric array.
 * Returns 0 for empty arrays.
 */
export function calculateMedian(arr: number[]): number {
  const arrSize = arr.length;

  if (arrSize === 0) return 0;
  const sortedArr = [...arr].sort((a, b) => a - b);

  if (arrSize % 2 !== 0) {
    return sortedArr[Math.floor(arrSize / 2)]!;
  }

  const mid1 = sortedArr[arrSize / 2 - 1]!;
  const mid2 = sortedArr[arrSize / 2]!;
  return (mid1 + mid2) / 2;
}
