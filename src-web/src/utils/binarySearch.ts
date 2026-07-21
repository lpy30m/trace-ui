/** Find exact index of targetSeq in sorted array. Returns -1 if not found. */
export function findSeqIndex(matchSeqs: number[], targetSeq: number): number {
  let lo = 0, hi = matchSeqs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (matchSeqs[mid] === targetSeq) return mid;
    if (matchSeqs[mid] < targetSeq) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/** Find index of nearest seq to targetSeq in sorted array. Returns -1 if empty. */
export function findNearestSeqIndex(matchSeqs: number[], targetSeq: number): number {
  if (matchSeqs.length === 0) return -1;
  let lo = 0, hi = matchSeqs.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (matchSeqs[mid] < targetSeq) lo = mid + 1;
    else hi = mid;
  }
  // lo is first seq >= targetSeq; compare with lo-1
  if (lo > 0 && Math.abs(matchSeqs[lo - 1] - targetSeq) <= Math.abs(matchSeqs[lo] - targetSeq)) {
    return lo - 1;
  }
  return lo;
}
