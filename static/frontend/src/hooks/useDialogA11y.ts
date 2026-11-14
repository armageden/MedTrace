import { useEffect, useRef, type RefObject } from 'react';

export interface UseDialogA11yOptions {
  isOpen: boolean;
  onClose: () => void;
  containerRef: RefObject<HTMLElement | null>;
  initialFocusRef?: RefObject<HTMLElement | null>;
  restoreFocus?: boolean;
}

const activeDialogStack: symbol[] = [];

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

function isElementVisible(el: HTMLElement, root: HTMLElement): boolean {
  let current: HTMLElement | null = el;
  while (current) {
    if (current.hasAttribute('hidden') || current.hasAttribute('inert')) {
      return false;
    }
    if (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
      const style = window.getComputedStyle(current);
      if (style.display === 'none' || style.visibility === 'hidden') {
        return false;
      }
    }
    if (current === root) {
      break;
    }
    current = current.parentElement;
  }
  return true;
}

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  const candidates = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
  return candidates.filter((el) => {
    if ((el as HTMLButtonElement).disabled || el.hasAttribute('disabled')) {
      return false;
    }
    if (el.tabIndex < 0) {
      return false;
    }
    return isElementVisible(el, container);
  });
}

function removeFromStack(dialogId: symbol): void {
  const index = activeDialogStack.lastIndexOf(dialogId);
  if (index !== -1) {
    activeDialogStack.splice(index, 1);
  }
}

/**
 * Centralizes WCAG dialog keyboard and focus behavior:
 * - LIFO stack ensures `Escape` closes only the top-most open dialog.
 * - Captures `document.activeElement` on open and restores focus on close/unmount.
 * - Moves initial focus into the dialog and traps `Tab` / `Shift+Tab` inside focusable descendants.
 */
export function useDialogA11y({
  isOpen,
  onClose,
  containerRef,
  initialFocusRef,
  restoreFocus = true,
}: UseDialogA11yOptions): void {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const dialogId = Symbol('medtrace-dialog');
    activeDialogStack.push(dialogId);

    const previouslyFocused =
      typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const container = containerRef.current;
    if (container) {
      const explicitTarget = initialFocusRef?.current;
      if (explicitTarget && isElementVisible(explicitTarget, container)) {
        explicitTarget.focus();
      } else {
        const focusables = getFocusableElements(container);
        if (focusables.length > 0) {
          focusables[0].focus();
        } else {
          if (!container.hasAttribute('tabindex')) {
            container.setAttribute('tabindex', '-1');
          }
          container.focus();
        }
      }
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (activeDialogStack[activeDialogStack.length - 1] !== dialogId) {
        return;
      }

      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current();
        return;
      }

      if (event.key !== 'Tab') {
        return;
      }

      const activeContainer = containerRef.current;
      if (!activeContainer) {
        return;
      }

      const focusables = getFocusableElements(activeContainer);
      if (focusables.length === 0) {
        event.preventDefault();
        if (!activeContainer.hasAttribute('tabindex')) {
          activeContainer.setAttribute('tabindex', '-1');
        }
        activeContainer.focus();
        return;
      }

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const activeEl =
        typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;

      if (!activeEl || !activeContainer.contains(activeEl) || focusables.indexOf(activeEl) === -1) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }

      if (event.shiftKey) {
        if (activeEl === first) {
          event.preventDefault();
          last.focus();
        }
      } else if (activeEl === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      removeFromStack(dialogId);
      if (restoreFocus && previouslyFocused && previouslyFocused.isConnected) {
        previouslyFocused.focus();
      }
    };
  }, [isOpen, containerRef, initialFocusRef, restoreFocus]);
}
