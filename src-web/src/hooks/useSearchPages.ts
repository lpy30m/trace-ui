import { useRef, useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

/** 每页大小，与后端 SEARCH_FIRST_PAGE_SIZE 一致 */
const PAGE_SIZE = 5000;

interface SearchPageResult {
  generation: number;
  seqs: number[];
}

export interface UseSearchPagesReturn {
  /** 搜索结果总条数 */
  totalCount: number;
  /** 获取指定索引位置的 seq（未加载则返回 undefined 并触发加载） */
  getSeqAtIndex: (index: number) => number | undefined;
  /** 批量确保某个索引范围的页已加载 */
  ensureRange: (startIndex: number, endIndex: number) => void;
  /** 指定 seq 在已加载页中的索引（二分查找），未找到返回 -1 */
  findSeqIndex: (seq: number) => number;
  /** 重置状态（新搜索时调用） */
  reset: (total: number, firstPage: number[], sessionId: string) => void;
  /** 页加载版本号（变更时触发 re-render） */
  pageVersion: number;
}

export function useSearchPages(): UseSearchPagesReturn {
  const [totalCount, setTotalCount] = useState(0);
  const [pageVersion, setPageVersion] = useState(0);

  const pagesRef = useRef<Map<number, number[]>>(new Map());
  const inflightRef = useRef<Set<number>>(new Set());
  const sessionIdRef = useRef("");
  const genRef = useRef(0);

  const reset = useCallback((total: number, firstPage: number[], sessionId: string) => {
    genRef.current++;
    pagesRef.current.clear();
    inflightRef.current.clear();
    sessionIdRef.current = sessionId;
    setTotalCount(total);
    if (firstPage.length > 0) {
      pagesRef.current.set(0, firstPage);
    }
    setPageVersion(v => v + 1);
  }, []);

  const loadPage = useCallback((pageIndex: number) => {
    if (inflightRef.current.has(pageIndex) || pagesRef.current.has(pageIndex)) return;
    if (!sessionIdRef.current) return;

    inflightRef.current.add(pageIndex);
    const localGen = genRef.current;
    const offset = pageIndex * PAGE_SIZE;

    invoke<SearchPageResult>("fetch_search_page", {
      sessionId: sessionIdRef.current,
      offset,
      count: PAGE_SIZE,
    }).then((result) => {
      inflightRef.current.delete(pageIndex);
      if (localGen !== genRef.current) return;
      pagesRef.current.set(pageIndex, result.seqs);
      setPageVersion(v => v + 1);
    }).catch(() => {
      inflightRef.current.delete(pageIndex);
    });
  }, []);

  const getSeqAtIndex = useCallback((index: number): number | undefined => {
    const pageIndex = Math.floor(index / PAGE_SIZE);
    const offset = index % PAGE_SIZE;
    const page = pagesRef.current.get(pageIndex);
    if (page) return page[offset];
    loadPage(pageIndex);
    return undefined;
  }, [loadPage]);

  const ensureRange = useCallback((startIndex: number, endIndex: number) => {
    const startPage = Math.floor(startIndex / PAGE_SIZE);
    const endPage = Math.floor(Math.max(0, endIndex) / PAGE_SIZE);
    for (let p = startPage; p <= endPage; p++) {
      if (!pagesRef.current.has(p)) {
        loadPage(p);
      }
    }
  }, [loadPage]);

  const findSeqIndex = useCallback((seq: number): number => {
    // 按页号排序遍历，每页内二分查找
    const sortedKeys = Array.from(pagesRef.current.keys()).sort((a, b) => a - b);
    for (const pageIndex of sortedKeys) {
      const page = pagesRef.current.get(pageIndex)!;
      if (page.length === 0) continue;
      if (seq < page[0]) continue;
      if (seq > page[page.length - 1]) continue;
      // seq 在此页范围内，二分查找
      let lo = 0, hi = page.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (page[mid] === seq) return pageIndex * PAGE_SIZE + mid;
        if (page[mid] < seq) lo = mid + 1;
        else hi = mid - 1;
      }
      // 最近匹配
      return pageIndex * PAGE_SIZE + lo;
    }
    return -1;
  }, []);

  return {
    totalCount,
    getSeqAtIndex,
    ensureRange,
    findSeqIndex,
    reset,
    pageVersion,
  };
}
