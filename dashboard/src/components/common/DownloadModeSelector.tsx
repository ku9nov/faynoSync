import React from 'react';
import { DownloadMode } from '@/hooks/use-query/useAppsQuery';
import { FIELD_LABEL } from '@/components/common/ui';

const DOWNLOAD_MODES: { value: DownloadMode; label: string; description: string }[] = [
  {
    value: 'strict',
    label: 'Strict',
    description: 'Only clients with a download token or dashboard users with access can download',
  },
  {
    value: 'unlisted',
    label: 'Unlisted',
    description: 'Anyone who has the /download link can download',
  },
];

interface DownloadModeSelectorProps {
  value: DownloadMode | null;
  onChange: (mode: DownloadMode) => void;
  hint?: string;
}

export const DownloadModeSelector: React.FC<DownloadModeSelectorProps> = ({ value, onChange, hint }) => (
  <div role="radiogroup" aria-label="Download mode">
    <span className={FIELD_LABEL}>Download mode</span>
    <div className="flex flex-col gap-2">
      {DOWNLOAD_MODES.map((mode) => {
        const selected = value === mode.value;
        return (
          <label
            key={mode.value}
            className="flex cursor-pointer select-none items-start gap-3 rounded-lg border border-white/15 bg-violet-950/40 px-3 py-2 transition-colors hover:bg-violet-950/60"
          >
            <input
              type="radio"
              name="download-mode"
              value={mode.value}
              checked={selected}
              onChange={() => onChange(mode.value)}
              className="peer sr-only"
            />
            <span
              className={`mt-0.5 flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border bg-violet-950/40 transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-white/70 ${
                selected ? 'border-violet-500' : 'border-white/40'
              }`}
            >
              {selected && <span className="h-2 w-2 rounded-full bg-violet-500"></span>}
            </span>
            <span>
              <span className={`block text-[13px] font-semibold transition-colors ${selected ? 'text-violet-300' : 'text-white/70'}`}>
                {mode.label}
              </span>
              <span className="mt-0.5 block text-xs text-white/55">{mode.description}</span>
            </span>
          </label>
        );
      })}
    </div>
    {hint && <p className="mt-2 text-xs text-white/55">{hint}</p>}
  </div>
);
