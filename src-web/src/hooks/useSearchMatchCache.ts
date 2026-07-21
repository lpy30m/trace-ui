import { useRef, useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SearchMatch } from "../types/trace";

interface SearchQueryParams {
  query: string;
  caseSensitive: boolean;
  useRegex: boolean;
  fuzzy: boolean;
}

interface UseSearchMatchCacheReturn {
  /** Get cached matches for given seqs. Returns what's available, triggers fetch for missing. */
  getMatches: (seqs: number[]) => (SearchMatch | undefined)[];
  /** Get single cached match */
  getMatch: (seq: number) => SearchMatch | undefined;
  /** Request details immediately without debounce (for page-load coupling) */
  requestImmediate: (seqs: number[]) => void;
  /** Clear all cached data (call on new search) */
  clear: () => void;
  /** Number of cached entries (for triggering effects) */
  cacheSize: number;
}

export function useSearchMatchCache(
  sessionId: string | null,
  queryParams: SearchQueryParams | null,
  generation: number,
): UseSearchMatchCacheReturn {
  const cacheRef = useRef<Map<number, SearchMatch>>(new Map());
  const inflightRef = useRef<Set<number>>(new Set());
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingRef = useRef<Set<number>>(new Set());
  const genRef = useRef(generation);
  genRef.current = generation;
  const [cacheSize, setCacheSize] = useState(0);

  const flush = useCallback(() => {
    if (!sessionId || !queryParams || pendingRef.current.size === 0) return;

    const seqs = Array.from(pendingRef.current);
    pendingRef.current.clear();

    // Mark as inflight
    for (const s of seqs) inflightRef.current.add(s);

    const gen = genRef.current;
    invoke<SearchMatch[]>("get_search_matches", {
      sessionId,
      request: {
        seqs,
        query: queryParams.query,
        case_sensitive: queryParams.caseSensitive,
        use_regex: queryParams.useRegex,
        fuzzy: queryParams.fuzzy,
      },
    }).then((matches) => {
      // gen 不匹配时仍需清理 inflightRef，否则这些 seq 会永久卡在 inflight 状态
      if (gen !== genRef.current) {
        for (const s of seqs) inflightRef.current.delete(s);
        return;
      }
      for (const m of matches) {
        cacheRef.current.set(m.seq, m);
        inflightRef.current.delete(m.seq);
      }
      for (const s of seqs) inflightRef.current.delete(s);
      setCacheSize(cacheRef.current.size);
    }).catch(() => {
      for (const s of seqs) inflightRef.current.delete(s);
    });
  }, [sessionId, queryParams]);

  const scheduleFlush = useCallback((immediate: boolean) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (immediate) {
      flush();
    } else {
      timerRef.current = setTimeout(flush, 50);
    }
  }, [flush]);

  const getMatches = useCallback((seqs: number[]): (SearchMatch | undefined)[] => {
    const result: (SearchMatch | undefined)[] = [];
    let hasMissing = false;
    for (const seq of seqs) {
      const cached = cacheRef.current.get(seq);
      result.push(cached);
      if (!cached && !inflightRef.current.has(seq) && !pendingRef.current.has(seq)) {
        pendingRef.current.add(seq);
        hasMissing = true;
      }
    }
    if (hasMissing) {
      // First fetch (cache empty) → immediate; subsequent → debounced
      scheduleFlush(cacheRef.current.size === 0);
    }
    return result;
  }, [scheduleFlush]);

  /** 立即请求详情，跳过 debounce（用于 onPageLoaded 耦合） */
  const requestImmediate = useCallback((seqs: number[]) => {
    let hasMissing = false;
    for (const seq of seqs) {
      if (!cacheRef.current.has(seq) && !inflightRef.current.has(seq) && !pendingRef.current.has(seq)) {
        pendingRef.current.add(seq);
        hasMissing = true;
      }
    }
    if (hasMissing) flush();
  }, [flush]);

  const getMatch = useCallback((seq: number): SearchMatch | undefined => {
    return cacheRef.current.get(seq);
  }, []);

  const clear = useCallback(() => {
    cacheRef.current.clear();
    inflightRef.current.clear();
    pendingRef.current.clear();
    if (timerRef.current) clearTimeout(timerRef.current);
    setCacheSize(0);
  }, []);

  return { getMatches, getMatch, requestImmediate, clear, cacheSize };
}
