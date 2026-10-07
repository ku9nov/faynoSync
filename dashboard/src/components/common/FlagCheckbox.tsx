import React from 'react';

// Checkbox, not a toggle chip: the box has to look clickable before it is clicked.
const FLAG_TONE = {
  green: { box: 'peer-checked:border-green-500 peer-checked:bg-green-500', text: 'peer-checked:text-green-300' },
  red: { box: 'peer-checked:border-red-500 peer-checked:bg-red-500', text: 'peer-checked:text-red-300' },
  amber: { box: 'peer-checked:border-amber-500 peer-checked:bg-amber-500', text: 'peer-checked:text-amber-300' },
  violet: { box: 'peer-checked:border-violet-500 peer-checked:bg-violet-500', text: 'peer-checked:text-violet-300' },
} as const;

interface FlagCheckboxProps {
  label: string;
  description?: string;
  tone?: keyof typeof FLAG_TONE;
  checked?: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

export const FlagCheckbox: React.FC<FlagCheckboxProps> = ({
  label,
  description,
  tone = 'violet',
  checked,
  disabled = false,
  onChange,
}) => (
  <label
    className={`flex select-none rounded-lg border border-white/15 bg-violet-950/40 px-3 py-2 transition-colors ${
      description ? 'items-start gap-3' : 'items-center gap-2.5'
    } ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:bg-violet-950/60'}`}
  >
    <input
      type="checkbox"
      checked={Boolean(checked)}
      disabled={disabled}
      onChange={(e) => onChange(e.target.checked)}
      className="peer sr-only"
    />
    <span
      className={`flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-[5px] border border-white/40 bg-violet-950/40 text-transparent transition-colors peer-checked:text-white peer-focus-visible:ring-2 peer-focus-visible:ring-white/70 ${
        description ? 'mt-0.5' : ''
      } ${FLAG_TONE[tone].box}`}
    >
      <i className="fas fa-check text-[10px]"></i>
    </span>
    <span>
      <span className={`block text-[13px] font-semibold text-white/70 transition-colors ${FLAG_TONE[tone].text}`}>
        {label}
      </span>
      {description && <span className="mt-0.5 block text-xs text-white/55">{description}</span>}
    </span>
  </label>
);
