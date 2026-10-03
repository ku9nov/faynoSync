import React, { useState } from 'react';
import { Updater } from '@/hooks/use-query/usePlatformQuery';
import { NOTE_WARNING, ROW_TILE, SECTION_LABEL, STATUS_BADGE } from './ui';

interface UpdatersSelectorProps {
  updaters: Updater[];
  onChange: (updaters: Updater[]) => void;
}

const AVAILABLE_UPDATERS = [
  {
    type: 'manual',
    label: 'Manual',
    description: 'Manual update process',
    icon: 'fas fa-wrench',
  },
  {
    type: 'squirrel_darwin',
    label: 'Squirrel (Darwin)',
    description: 'Squirrel updater for macOS',
    icon: 'fab fa-apple',
  },
  {
    type: 'squirrel_windows',
    label: 'Squirrel (Windows)',
    description: 'Squirrel updater for Windows',
    icon: 'fab fa-windows',
  },
  {
    type: 'sparkle',
    label: 'Sparkle',
    description: 'Sparkle framework for macOS updates',
    icon: 'fas fa-magic',
  },
  {
    type: 'electron-builder',
    label: 'Electron Builder',
    description: 'Electron Builder update mechanism',
    icon: 'fas fa-atom',
  },
  {
    type: 'tauri',
    label: 'Tauri',
    description: 'Tauri framework update mechanism',
    icon: 'fas fa-rocket',
  },
  {
    type: 'velopack',
    label: 'Velopack',
    description: 'Velopack update mechanism',
    icon: 'fas fa-box',
  },
];

export const UpdatersSelector: React.FC<UpdatersSelectorProps> = ({ updaters, onChange }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const handleUpdaterToggle = (updaterType: string, checked: boolean) => {
    // Prevent disabling manual updater
    if (updaterType === 'manual' && !checked) {
      return;
    }

    if (checked) {
      // Add updater if not already present
      if (!updaters.find(u => u.type === updaterType)) {
        const newUpdaters = [...updaters, { type: updaterType }];
        
        // If this is the first updater, set it as default
        if (newUpdaters.length === 1) {
          newUpdaters[0].default = true;
        } else if (updaterType === 'manual' && !newUpdaters.some(u => u.default)) {
          // If adding manual and no default is set, set manual as default
          const manualUpdater = newUpdaters.find(u => u.type === 'manual');
          if (manualUpdater) {
            manualUpdater.default = true;
          }
        }
        
        onChange(newUpdaters);
      }
    } else {
      // Remove updater
      const newUpdaters = updaters.filter(u => u.type !== updaterType);
      
      // If we're removing the default updater and there are other updaters, set manual as default
      const removedUpdater = updaters.find(u => u.type === updaterType);
      if (removedUpdater?.default && newUpdaters.length > 0) {
        const manualUpdater = newUpdaters.find(u => u.type === 'manual');
        if (manualUpdater) {
          manualUpdater.default = true;
        } else {
          newUpdaters[0].default = true;
        }
      }
      
      onChange(newUpdaters);
    }
  };

  const handleDefaultToggle = (updaterType: string, checked: boolean) => {
    const newUpdaters = updaters.map(updater => ({
      ...updater,
      default: updater.type === updaterType ? checked : false
    }));
    
    // Ensure at least one updater is set as default
    if (!checked && newUpdaters.every(u => !u.default)) {
      // If we're unchecking the only default updater, set manual as default
      const manualUpdater = newUpdaters.find(u => u.type === 'manual');
      if (manualUpdater) {
        manualUpdater.default = true;
      } else if (newUpdaters.length > 0) {
        newUpdaters[0].default = true;
      }
    }
    
    onChange(newUpdaters);
  };

  const isUpdaterSelected = (updaterType: string) => {
    return updaters.some(u => u.type === updaterType);
  };

  const isUpdaterDefault = (updaterType: string) => {
    return updaters.find(u => u.type === updaterType)?.default || false;
  };

  const handleExpandClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    e.nativeEvent.stopImmediatePropagation();
    
    setIsExpanded(!isExpanded);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <p className={SECTION_LABEL}>Updaters</p>
        <span className="font-mono text-[11px] tabular-nums text-white/60">{updaters.length}</span>
        <button
          onClick={handleExpandClick}
          onMouseDown={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onMouseUp={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          className="rounded-md p-1.5 text-white/70 transition-colors hover:bg-white/10 hover:text-theme-primary"
          aria-label={isExpanded ? 'Collapse updaters' : 'Expand updaters'}
        >
          <svg
            className={`w-4 h-4 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>

      {isExpanded && (
        <>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {AVAILABLE_UPDATERS.map(({ type, label, description, icon }) => {
              const isSelected = isUpdaterSelected(type);
              const isDefault = isUpdaterDefault(type);

              return (
                <div
                  key={type}
                  className={`relative rounded-lg border p-4 transition-colors ${
                    isSelected
                      ? 'border-violet-400/60 bg-violet-500/10'
                      : 'border-white/15 bg-violet-950/30 hover:bg-violet-950/50'
                  } ${type === 'manual' ? 'cursor-default' : 'cursor-pointer'}`}
                  onClick={() => handleUpdaterToggle(type, !isSelected)}
                >
                  <div className="flex items-start gap-3">
                    <span className={ROW_TILE}>
                      <i className={`${icon} text-white/90`}></i>
                    </span>
                    <div className="min-w-0 flex-1">
                      <h4 className="text-[14.5px] font-bold text-theme-primary">{label}</h4>
                      <p className="mt-0.5 text-xs leading-relaxed text-white/60">{description}</p>
                    </div>
                    <span
                      className={`flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border transition-colors ${
                        isSelected ? 'border-violet-400 bg-violet-500 text-white' : 'border-white/40 text-transparent'
                      }`}
                    >
                      <i className="fas fa-check text-[9px]"></i>
                    </span>
                  </div>

                  {type === 'manual' && (
                    <p className="mt-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-white/45">
                      Always enabled
                    </p>
                  )}

                  {isSelected && (
                    <div className="mt-3 border-t border-white/15 pt-3" onClick={(e) => e.stopPropagation()}>
                      <label className="flex cursor-pointer items-center gap-2">
                        <input
                          type="radio"
                          name="default-updater"
                          checked={isDefault}
                          onChange={(e) => {
                            e.stopPropagation();
                            handleDefaultToggle(type, e.target.checked);
                          }}
                          className="peer sr-only"
                        />
                        <span
                          className={`flex h-4 w-4 items-center justify-center rounded-full border transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-white/70 ${
                            isDefault ? 'border-violet-400 bg-violet-500' : 'border-white/40'
                          }`}
                        >
                          {isDefault && <span className="h-1.5 w-1.5 rounded-full bg-white"></span>}
                        </span>
                        <span
                          className={`text-xs font-semibold transition-colors ${
                            isDefault ? 'text-violet-300' : 'text-white/60'
                          }`}
                        >
                          Set as default
                        </span>
                      </label>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {updaters.length === 0 && (
            <div className={NOTE_WARNING}>
              <i className="fas fa-exclamation-triangle"></i>
              No updaters selected — pick at least one.
            </div>
          )}
        </>
      )}

      {updaters.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {updaters.map((updater) => {
            const updaterInfo = AVAILABLE_UPDATERS.find(u => u.type === updater.type);
            return (
              <span
                key={updater.type}
                className={`${STATUS_BADGE} ${
                  updater.default ? 'border-violet-400/60 text-violet-200' : 'border-white/15 text-white/75'
                }`}
              >
                <i className={`${updaterInfo?.icon} text-[12px] opacity-90`}></i>
                {updaterInfo?.label}
                {updater.default && (
                  <span className="rounded-full bg-white/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.06em]">
                    Default
                  </span>
                )}
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
};
