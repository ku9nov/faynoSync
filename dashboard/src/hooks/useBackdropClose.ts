import { useRef } from 'react';
import type { MouseEvent } from 'react';

export function useBackdropClose(onClose: () => void, enabled = true) {
  const downOnBackdrop = useRef(false);

  return {
    onMouseDown: (e: MouseEvent) => {
      downOnBackdrop.current = e.target === e.currentTarget;
    },
    onClick: (e: MouseEvent) => {
      if (enabled && e.target === e.currentTarget && downOnBackdrop.current) {
        onClose();
      }
    },
  };
}

export default useBackdropClose;
