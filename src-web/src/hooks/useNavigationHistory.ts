import { useState, useCallback, useRef } from "react";

const MAX_HISTORY = 300;

interface NavState {
  history: number[];
  currentIndex: number;
}

const INIT_STATE: NavState = { history: [], currentIndex: -1 };

export function useNavigationHistory(setSelectedSeq: (seq: number) => void) {
  const [state, setState] = useState<NavState>(INIT_STATE);
  // 标记当前跳转是 back/forward 触发的，不应产生新历史条目
  const isNavigating = useRef(false);

  const navigate = useCallback((seq: number) => {
    if (isNavigating.current) {
      isNavigating.current = false;
      setSelectedSeq(seq);
      return;
    }

    setState((prev) => {
      const base = prev.history.slice(0, prev.currentIndex + 1);

      const next = [...base, seq];
      if (next.length > MAX_HISTORY) {
        const trimmed = next.slice(next.length - MAX_HISTORY);
        return { history: trimmed, currentIndex: trimmed.length - 1 };
      }
      return { history: next, currentIndex: next.length - 1 };
    });

    setSelectedSeq(seq);
  }, [setSelectedSeq]);

  const canGoBack = state.currentIndex > 0;
  const canGoForward = state.currentIndex < state.history.length - 1;

  const goBack = useCallback(() => {
    setState((prev) => {
      if (prev.currentIndex <= 0) return prev;
      const newIndex = prev.currentIndex - 1;
      isNavigating.current = true;
      setSelectedSeq(prev.history[newIndex]);
      return { ...prev, currentIndex: newIndex };
    });
  }, [setSelectedSeq]);

  const goForward = useCallback(() => {
    setState((prev) => {
      if (prev.currentIndex >= prev.history.length - 1) return prev;
      const newIndex = prev.currentIndex + 1;
      isNavigating.current = true;
      setSelectedSeq(prev.history[newIndex]);
      return { ...prev, currentIndex: newIndex };
    });
  }, [setSelectedSeq]);

  return { navigate, goBack, goForward, canGoBack, canGoForward };
}
