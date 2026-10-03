import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { DROPDOWN_MENU, DROPDOWN_MENU_STYLE, DROPDOWN_TRIGGER } from './ui';

export interface DropdownOption<T = string> {
  value: T;
  label: string;
  icon?: string;
}

interface DropdownProps<T> {
  options: DropdownOption<T>[];
  value: T | T[];
  onChange: (value: T) => void;
  placeholder?: string;
  multiple?: boolean;
  disabled?: boolean;
  emptyMessage?: string;
  ariaLabel?: string;
  className?: string;
  triggerClassName?: string;
  menuClassName?: string;
}

const isSelected = <T,>(value: T | T[], option: T) =>
  Array.isArray(value) ? value.includes(option) : value === option;

export function Dropdown<T>({
  options,
  value,
  onChange,
  placeholder = 'Select',
  multiple = false,
  disabled = false,
  emptyMessage = 'No options available',
  ariaLabel,
  className = '',
  triggerClassName = '',
  menuClassName = '',
}: DropdownProps<T>) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const listId = useId();

  const selectedOptions = options.filter(option => isSelected(value, option.value));
  const triggerLabel = multiple
    ? selectedOptions.length > 0
      ? `${selectedOptions.length} selected`
      : placeholder
    : selectedOptions[0]?.label ?? placeholder;
  const hasValue = multiple ? selectedOptions.length > 0 : selectedOptions.length === 1;

  const close = useCallback((returnFocus = false) => {
    setOpen(false);
    setActiveIndex(-1);
    if (returnFocus) {
      triggerRef.current?.focus();
    }
  }, []);

  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        close();
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    return () => document.removeEventListener('mousedown', handlePointerDown);
  }, [open, close]);

  // Keep the highlighted option in view while arrowing through a long list.
  useEffect(() => {
    if (!open || activeIndex < 0) return;
    const activeNode = listRef.current?.children[activeIndex] as HTMLElement | undefined;
    activeNode?.scrollIntoView({ block: 'nearest' });
  }, [open, activeIndex]);

  const handleSelect = (option: DropdownOption<T>) => {
    onChange(option.value);
    if (!multiple) {
      close(true);
    }
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (disabled) return;

    if (event.key === 'Escape') {
      if (open) {
        event.stopPropagation();
        close(true);
      }
      return;
    }

    if (event.key === 'Tab') {
      close();
      return;
    }

    if (!open) {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        setOpen(true);
        setActiveIndex(
          options.findIndex(option => isSelected(value, option.value)) >= 0
            ? options.findIndex(option => isSelected(value, option.value))
            : 0
        );
      }
      return;
    }

    if (options.length === 0) return;

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        setActiveIndex(index => (index + 1) % options.length);
        break;
      case 'ArrowUp':
        event.preventDefault();
        setActiveIndex(index => (index <= 0 ? options.length - 1 : index - 1));
        break;
      case 'Home':
        event.preventDefault();
        setActiveIndex(0);
        break;
      case 'End':
        event.preventDefault();
        setActiveIndex(options.length - 1);
        break;
      case 'Enter':
      case ' ':
        event.preventDefault();
        if (activeIndex >= 0) {
          handleSelect(options[activeIndex]);
        }
        break;
    }
  };

  return (
    <div ref={containerRef} className={`relative ${className}`} onKeyDown={handleKeyDown}>
      <button
        ref={triggerRef}
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls={open ? listId : undefined}
        aria-activedescendant={open && activeIndex >= 0 ? `${listId}-${activeIndex}` : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => (open ? close() : setOpen(true))}
        className={`${DROPDOWN_TRIGGER} focus:outline-none focus-visible:ring-2 focus-visible:ring-white/70 disabled:cursor-not-allowed disabled:opacity-50 ${triggerClassName}`}
      >
        <span className={`block min-w-0 flex-1 truncate text-left ${hasValue ? '' : 'text-white/55'}`}>
          {!multiple && selectedOptions[0]?.icon && (
            <i className={`${selectedOptions[0].icon} mr-2 opacity-90`}></i>
          )}
          {triggerLabel}
        </span>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
          className={`ml-2 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`}
        >
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </button>

      {open && (
        <div
          ref={listRef}
          id={listId}
          role="listbox"
          aria-multiselectable={multiple || undefined}
          aria-label={ariaLabel}
          className={`${DROPDOWN_MENU} max-h-60 overflow-y-auto ${menuClassName}`}
          style={DROPDOWN_MENU_STYLE}
        >
          {options.length === 0 ? (
            <p className="px-4 py-3 text-center text-sm text-white/55">{emptyMessage}</p>
          ) : (
            options.map((option, index) => {
              const selected = isSelected(value, option.value);
              return (
                <button
                  key={`${listId}-${index}`}
                  id={`${listId}-${index}`}
                  type="button"
                  role="option"
                  aria-selected={selected}
                  tabIndex={-1}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => handleSelect(option)}
                  className={`flex w-full items-center gap-2 px-4 py-2 text-left text-theme-primary transition-colors first:rounded-t-lg last:rounded-b-lg ${
                    index === activeIndex ? 'bg-white/15' : ''
                  } ${selected ? 'font-semibold' : ''}`}
                >
                  {option.icon && <i className={`${option.icon} w-4 text-center opacity-90`}></i>}
                  <span className="min-w-0 flex-1 truncate">{option.label}</span>
                  {selected && <i className="fas fa-check text-xs text-violet-300"></i>}
                </button>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
