import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { Artifact, useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { DeleteArtifactConfirmationModal } from '@/components/modals/DeleteArtifactConfirmationModal';
import { AxiosError } from 'axios';
import axiosInstance from '@/config/axios';
import { BaseModal } from '@/components/common/BaseModal';
import { useQueryClient, useQuery } from '@tanstack/react-query';
import { AppListItem } from '@/hooks/use-query/useAppsQuery';
import { useToast } from '@/hooks/useToast';
import { getPlatformIcon } from '@/utils/platformIcon';
import { Dropdown } from '@/components/common/Dropdown';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { ModalFeedback } from '@/components/common/ModalFeedback';
import {
  ACTION_BUTTON,
  ACTION_GROUP,
  BTN_GHOST,
  BTN_PRIMARY,
  BTN_WARNING,
  DROPZONE,
  FIELD_INPUT,
  FIELD_LABEL,
  MARKDOWN_PREVIEW,
  NOTE_WARNING,
  ROW,
  ROW_META,
  ROW_TILE,
  ROW_TITLE,
  SECTION_LABEL,
  SEGMENTED_GROUP,
  STATUS_BADGE,
  STATUS_DOT,
  TUF_BADGE_STYLE,
  segmentedButton,
} from '@/components/common/ui';
import type { TufStatus } from '@/components/common/ui';

const SECTION = `${SECTION_LABEL} mt-6 mb-2`;

interface EditVersionModalProps {
  appName: string;
  version: string;
  channel: string;
  currentData: {
    ID: string;
    Published: boolean;
    Critical: boolean;
    Intermediate: boolean;
    RolloutPercent?: number | null;
    Changelog: string;
    Artifacts: Artifact[];
  };
  onClose: () => void;
  onSave: (data: {
    Published: boolean;
    Critical: boolean;
    Intermediate: boolean;
    Changelog: string;
    Platform?: string;
    Arch?: string;
    Files: File[];
    app_name: string;
    version: string;
    channel: string;
    updater?: string;
    rollout: number;
  }) => void;
}
interface ErrorResponse {
  error: string;
  details?: string;
}

// 0 and 100 are states, not just numbers — each zone owns its badge and its sentence.
const ROLLOUT_ZONES = [
  { max: 0, label: 'Paused', badge: 'text-slate-200 border-slate-400/40', dot: 'bg-slate-400' },
  { max: 9, label: 'Canary', badge: 'text-amber-300 border-amber-500/45', dot: 'bg-amber-500' },
  { max: 99, label: 'Ramping', badge: 'text-blue-300 border-blue-500/45', dot: 'bg-blue-500' },
  { max: 100, label: 'Full rollout', badge: 'text-green-300 border-green-500/40', dot: 'bg-green-500' },
];

const ROLLOUT_TICKS = Array.from({ length: 21 }, (_, i) => i * 5);

const clampRollout = (value: number) => Math.max(0, Math.min(100, Math.round(value || 0)));

interface RolloutSliderProps {
  value: number;
  channel: string;
  onChange: (value: number) => void;
}

const RolloutSlider: React.FC<RolloutSliderProps> = ({ value, channel, onChange }) => {
  const zone = ROLLOUT_ZONES.find(z => value <= z.max) ?? ROLLOUT_ZONES[ROLLOUT_ZONES.length - 1];

  const hint =
    value === 0
      ? 'Paused — no new device is offered this version.'
      : value === 100
      ? `Every device on ${channel} is offered this version.`
      : `Offered to ${value} of every 100 devices on ${channel}.`;

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div className="flex items-baseline gap-1 tabular-nums">
          <span className="text-[32px] font-extrabold leading-none tracking-tight text-theme-primary">{value}</span>
          <span className="text-sm font-semibold text-white/60">% of devices on {channel}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`${STATUS_BADGE} ${zone.badge}`}>
            <span className={`${STATUS_DOT} ${zone.dot}`}></span>
            {zone.label}
          </span>
          <div className="inline-flex items-stretch overflow-hidden rounded-lg border border-white/15 bg-violet-950/40">
            <input
              type="number"
              min={0}
              max={100}
              step={1}
              value={value}
              onChange={(e) => onChange(clampRollout(Number(e.target.value)))}
              className="w-14 bg-transparent py-2 text-center font-mono text-sm font-bold tabular-nums text-theme-primary focus:outline-none focus:ring-2 focus:ring-inset focus:ring-theme-focus [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
              aria-label="Rollout percent"
            />
            <button
              type="button"
              onClick={() => onChange(clampRollout(value - 5))}
              className="w-7 border-l border-white/15 bg-white/5 font-mono text-sm font-bold text-theme-primary transition-colors hover:bg-white/15"
              aria-label="Decrease by 5"
            >
              −
            </button>
            <button
              type="button"
              onClick={() => onChange(clampRollout(value + 5))}
              className="w-7 border-l border-white/15 bg-white/5 font-mono text-sm font-bold text-theme-primary transition-colors hover:bg-white/15"
              aria-label="Increase by 5"
            >
              +
            </button>
          </div>
        </div>
      </div>

      {/* The thumb travels between 9px insets, so the rail, ticks and bubble share that inset. */}
      <div className="relative h-[18px]">
        <span
          className="pointer-events-none absolute bottom-[22px] z-10 -translate-x-1/2 rounded-md bg-violet-400 px-2 py-[3px] font-mono text-xs font-bold tabular-nums text-violet-950"
          style={{ left: `calc(9px + (100% - 18px) * ${value} / 100)` }}
        >
          {value}%
        </span>
        <span className="absolute left-[9px] right-[9px] top-[6px] h-1.5 overflow-hidden rounded-full border border-white/15 bg-violet-950/45">
          <span
            className="absolute inset-y-0 left-0 bg-gradient-to-r from-violet-600 to-violet-400"
            style={{ width: `${value}%` }}
          ></span>
        </span>
        <input
          type="range"
          min={0}
          max={100}
          step={1}
          value={value}
          onChange={(e) => onChange(clampRollout(Number(e.target.value)))}
          className="rollout-range relative z-20 h-[18px] w-full cursor-pointer"
          aria-label="Staged rollout percent"
        />
      </div>

      <div className="relative mx-[9px] h-5" aria-hidden="true">
        {ROLLOUT_TICKS.map((tick) => (
          <React.Fragment key={tick}>
            <span
              className={`absolute top-0 w-px -translate-x-1/2 ${
                tick % 25 === 0 ? 'h-2 bg-white/55' : 'h-1 bg-white/25'
              }`}
              style={{ left: `${tick}%` }}
            ></span>
            {tick % 25 === 0 && (
              <span
                className="absolute top-[10px] -translate-x-1/2 font-mono text-[10px] font-semibold tabular-nums text-white/55"
                style={{ left: `${tick}%` }}
              >
                {tick}
              </span>
            )}
          </React.Fragment>
        ))}
      </div>

      <p className="mt-3 text-sm text-white/60">{hint}</p>
    </div>
  );
};

export const EditVersionModal: React.FC<EditVersionModalProps> = ({
  appName,
  version,
  channel,
  currentData,
  onClose,
  onSave,
}) => {
  const [formData, setFormData] = React.useState(currentData);
  const [rollout, setRollout] = React.useState<number>(currentData.RolloutPercent ?? 100);
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [isPreview, setIsPreview] = React.useState(false);
  const [platform, setPlatform] = React.useState<string>('');
  const [arch, setArch] = React.useState<string>('');
  const [updater, setUpdater] = React.useState<string>('');
  const [signature, setSignature] = React.useState<string>('');
  const [showDeleteConfirmation, setShowDeleteConfirmation] = React.useState(false);
  const [artifactToDelete, setArtifactToDelete] = React.useState<{ index: number; platform: string; arch: string } | null>(null);
  const [isLoading, setIsLoading] = React.useState(false);
  const [isSuccess, setIsSuccess] = React.useState(false);
  const [deleteError, setDeleteError] = useState<{ error: string; details?: string } | null>(null);
  const [deleteSuccess, setDeleteSuccess] = useState(false);
  const [unsignError, setUnsignError] = useState<{ error: string; details?: string } | null>(null);
  const [unsignSuccess, setUnsignSuccess] = useState(false);
  const [isUnsigning, setIsUnsigning] = useState(false);
  const pendingUnsignRef = React.useRef<Set<number>>(new Set());
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();
  const { deleteArtifact } = useAppsQuery();
  const queryClient = useQueryClient();
  const { toastSuccess, toastError } = useToast();
  const [error, setError] = useState<{ error: string; details?: string } | null>(null);
  const [isPublishingTuf, setIsPublishingTuf] = useState(false);

  // Get app data to check if TUF is enabled
  const { data: appData } = useQuery<AppListItem | null>({
    queryKey: ['appData', appName],
    queryFn: async () => {
      const response = await axiosInstance.get('/app/list');
      const app = response.data.apps.find((a: AppListItem) => a.AppName === appName);
      return app || null;
    },
    enabled: !!appName,
  });

  // Get selected platform and its updaters
  const selectedPlatform = platforms.find(p => p.PlatformName === platform);
  const availableUpdaters = selectedPlatform?.Updaters || [];
  const hasMultipleUpdaters = availableUpdaters.length > 1;
  const showUpdaterDropdown = hasMultipleUpdaters && platform;

  // Set default updater to 'manual' when dropdown is shown and no updater is selected
  React.useEffect(() => {
    if (showUpdaterDropdown && !updater) {
      setUpdater('manual');
    }
  }, [showUpdaterDropdown, updater]);

  const handleOptionClick = (dropdownName: string, value: string) => {
    if (dropdownName === 'platform') {
      setPlatform(value);
      // Reset updater when platform changes
      setUpdater('');
      setSignature('');
    } else if (dropdownName === 'arch') {
      setArch(value);
    } else if (dropdownName === 'updater') {
      setUpdater(value);
      setSignature('');
    }
  };

  React.useEffect(() => {
    setFormData(currentData);
    setRollout(currentData.RolloutPercent ?? 100);
  }, [currentData]);

  // Update formData when apps data is refetched after unsign operation
  React.useEffect(() => {
    const updateFormDataFromQuery = async () => {
      // Get all apps queries from cache
      const queryCache = queryClient.getQueryCache();
      const appsQueries = queryCache.findAll({ queryKey: ['apps'] });
      
      // Find the version with matching ID in any of the queries
      for (const query of appsQueries) {
        const data = query.state.data;
        if (!data) continue;
        
        let version: any = null;
        if (Array.isArray(data)) {
          version = data.find((item: any) => item.ID === currentData.ID);
        } else if (data && typeof data === 'object' && 'items' in data) {
          version = (data as any).items.find((item: any) => item.ID === currentData.ID);
        }
        
        if (version && version.Artifacts) {
          // Only update if we have pending unsign operations to check
          if (pendingUnsignRef.current.size > 0) {
            // Check if server has confirmed the unsign for pending artifacts
            const updatedArtifacts = version.Artifacts.map((artifact: Artifact, i: number) => {
              // If this artifact is pending unsign, check if server confirms it
              if (pendingUnsignRef.current.has(i)) {
                // If server confirms TufSigned is false, remove from pending
                if (artifact.TufSigned === false) {
                  pendingUnsignRef.current.delete(i);
                  return artifact;
                }
                // If server still shows TufSigned as true, keep our local change
                // Don't update this artifact from server yet
                const currentArtifact = formData.Artifacts[i];
                if (currentArtifact && currentArtifact.TufSigned === false) {
                  return currentArtifact;
                }
              }
              return artifact;
            });
            
            // Only update if we have changes or if all pending operations are confirmed
            setFormData(prev => ({
              ...prev,
              Artifacts: updatedArtifacts
            }));
          } else {
            // No pending operations, update normally
            setFormData(prev => ({
              ...prev,
              Artifacts: version.Artifacts
            }));
          }
          break;
        }
      }
    };

    // Set up a listener for query updates
    const unsubscribe = queryClient.getQueryCache().subscribe((event) => {
      if (event?.type === 'updated' && event.query.queryKey[0] === 'apps') {
        // Small delay to ensure data is fully updated
        setTimeout(updateFormDataFromQuery, 100);
      }
    });

    return () => {
      unsubscribe();
    };
  }, [queryClient, currentData.ID, formData.Artifacts]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsLoading(true);
    setError(null);
    try {
      const requestData = {
        ...formData,
        Files: selectedFiles,
        Platform: selectedFiles.length > 0 ? platform : undefined,
        Arch: selectedFiles.length > 0 ? arch : undefined,
        updater: selectedFiles.length > 0 && updater && updater !== 'manual' ? updater : undefined,
        signature: selectedFiles.length > 0 && updater === 'tauri' && signature ? signature : undefined,
        app_name: appName,
        version: version,
        channel: channel,
        rollout: rollout,
      };

      await onSave(requestData);
      setIsSuccess(true);
      setTimeout(() => {
        onClose();
      }, 500);
    } catch (err) {
      const axiosError = err as AxiosError<ErrorResponse>;
      if (axiosError.response?.data) {
        setError({
          error: axiosError.response.data.error || 'Failed to update',
          details: axiosError.response.data.details
        });
      } else {
        setError({
          error: 'Failed to update',
          details: axiosError.message
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.target.files) {
      const newFiles = Array.from(e.target.files);
      setSelectedFiles(prev => [...prev, ...newFiles]);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const removeFile = (indexToRemove: number) => {
    setSelectedFiles(prev => prev.filter((_, index) => index !== indexToRemove));
    if (indexToRemove === 0) {
      setPlatform('');
      setArch('');
      setUpdater('');
      setSignature('');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleDeleteArtifact = async (index: number, platform: string, arch: string) => {
    setArtifactToDelete({ index, platform, arch });
    setShowDeleteConfirmation(true);
  };

  const confirmDeleteArtifact = async () => {
    if (artifactToDelete) {
      try {
        setDeleteError(null);
        await deleteArtifact(currentData.ID, appName, version, artifactToDelete.index);
        const updatedArtifacts = formData.Artifacts.filter((_, i) => i !== artifactToDelete.index);
        setFormData(prev => ({
          ...prev,
          Artifacts: updatedArtifacts
        }));
        setDeleteSuccess(true);
        setTimeout(() => {
          setDeleteSuccess(false);
        }, 3000);
      } catch (error) {
        const axiosError = error as AxiosError<ErrorResponse>;
        if (axiosError.response?.data) {
          setDeleteError({
            error: axiosError.response.data.error || 'Failed to delete artifact',
            details: axiosError.response.data.details
          });
        } else {
          setDeleteError({
            error: 'Failed to delete artifact',
            details: axiosError.message
          });
        }
      }
      setShowDeleteConfirmation(false);
      setArtifactToDelete(null);
    }
  };

  // Mirrors getTufSignStatus in Dashboard.tsx so the modal reports the same state as the card.
  const tufStatus = React.useMemo<TufStatus | null>(() => {
    if (!appData?.Tuf) {
      return null;
    }
    // Feeds are the updater's index, not a TUF target: the server never signs them,
    // so counting them would leave every version stuck on 'partial'.
    const tufArtifacts = formData.Artifacts.filter(
      artifact =>
        !artifact.IsFeed &&
        (artifact.TufTaskID || (artifact.TufTaskID === null && artifact.TufSigned === false))
    );
    if (tufArtifacts.length === 0) {
      return formData.Artifacts.some(artifact => !artifact.IsFeed) ? 'none' : null;
    }
    const signedCount = tufArtifacts.filter(artifact => artifact.TufSigned === true).length;
    if (signedCount === tufArtifacts.length) {
      return 'all-signed';
    }
    return signedCount > 0 ? 'partial' : 'none';
  }, [appData?.Tuf, formData.Artifacts]);

  const unsignedCount = React.useMemo(
    () => formData.Artifacts.filter(artifact => artifact.TufSigned !== true && !artifact.IsFeed).length,
    [formData.Artifacts]
  );

  const hasValidArtifacts = React.useMemo(() => {
    return formData.Artifacts && 
           formData.Artifacts.length > 0 && 
           formData.Artifacts.some(artifact => 
             artifact.link
           );
  }, [formData.Artifacts]);

  const handleDownload = (artifact: Artifact) => {
    // First try to fetch the link with authentication
    axiosInstance.get(artifact.link)
      .then(response => {
        // Check if the response is JSON with a download_url
        if (response.data && typeof response.data === 'object' && 'download_url' in response.data) {
          // If it's a JSON with download_url, use that URL
          window.open(response.data.download_url, '_blank', 'noopener,noreferrer');
        } else {
          // Otherwise, it's a direct link to a file, use it directly
          window.open(artifact.link, '_blank', 'noopener,noreferrer');
        }
      })
      .catch(() => {
        // If there's an error (like 401), it might be a direct link to a public file
        // In that case, just open the link directly
        window.open(artifact.link, '_blank', 'noopener,noreferrer');
      });
  };

  const handleTufPublish = async () => {
    if (!appData?.ID) {
      toastError('App ID not found');
      return;
    }

    setIsPublishingTuf(true);

    try {
      const response = await axiosInstance.post('/tuf/v1/artifacts/publish', {
        app_id: appData.ID,
        version: version
      });
      
      // Extract task_id from response
      const responseData = response.data?.data;
      const taskId = responseData?.task_id;
      
      if (taskId) {
        // Save to localStorage history (similar to bootstrap)
        const savedHistory = localStorage.getItem('tuf-history');
        let history: Array<{
          id: string;
          timestamp: string;
          appName: string;
          operation: 'generate' | 'bootstrap' | 'publish' | 'unsign';
          status: 'success' | 'failed' | 'pending';
          taskId?: string;
          version?: string;
        }> = [];
        
        if (savedHistory) {
          try {
            history = JSON.parse(savedHistory);
          } catch (e) {
            console.error('Failed to load TUF history:', e);
          }
        }
        
        const newEntry = {
          id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
          timestamp: responseData.last_update || new Date().toISOString(),
          appName: appName,
          operation: 'publish' as const,
          status: 'pending' as const,
          taskId: taskId,
          version: version,
        };
        
        const updatedHistory = [newEntry, ...history].slice(0, 20); // Keep last 20 entries
        localStorage.setItem('tuf-history', JSON.stringify(updatedHistory));
      }
      
      toastSuccess(`TUF artifacts publishing successfully started for version ${version}`);
      
      // Invalidate and refetch queries to get updated data from server
      // Add a delay to allow server to process the request and update artifacts
      setTimeout(async () => {
        await queryClient.invalidateQueries({ queryKey: ['apps'] });
        await queryClient.invalidateQueries({ queryKey: ['appData', appName] });
        await queryClient.refetchQueries({ queryKey: ['apps'] });
        await queryClient.refetchQueries({ queryKey: ['appData', appName] });
      }, 2000);
      
      // Also refetch after a longer delay to catch status updates (when signing completes)
      setTimeout(async () => {
        await queryClient.refetchQueries({ queryKey: ['apps'] });
      }, 5000);
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to publish TUF artifacts';
      toastError(errorMessage);
      
      // Save failed operation to history
      const savedHistory = localStorage.getItem('tuf-history');
      let history: Array<{
        id: string;
        timestamp: string;
        appName: string;
        operation: 'generate' | 'bootstrap' | 'publish' | 'unsign';
        status: 'success' | 'failed' | 'pending';
        taskId?: string;
        version?: string;
      }> = [];
      
      if (savedHistory) {
        try {
          history = JSON.parse(savedHistory);
        } catch (e) {
          console.error('Failed to load TUF history:', e);
        }
      }
      
      const newEntry = {
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        appName: appName,
        operation: 'publish' as const,
        status: 'failed' as const,
        version: version,
      };
      
      const updatedHistory = [newEntry, ...history].slice(0, 20); // Keep last 20 entries
      localStorage.setItem('tuf-history', JSON.stringify(updatedHistory));
    } finally {
      setIsPublishingTuf(false);
    }
  };

  const handleUnsignArtifact = async (index: number) => {
    try {
      setIsUnsigning(true);
      setUnsignError(null);
      
      const requestData = {
        id: currentData.ID,
        app_name: appName,
        version: version,
        artifacts_to_delete: [index.toString()]
      };

      const response = await axiosInstance.post('/tuf/v1/artifacts/delete', JSON.stringify(requestData), {
        headers: {
          'Content-Type': 'text/plain',
        },
      });

      // Save to localStorage history (similar to publish)
      const savedHistory = localStorage.getItem('tuf-history');
      let history: Array<{
        id: string;
        timestamp: string;
        appName: string;
        operation: 'generate' | 'bootstrap' | 'publish' | 'unsign';
        status: 'success' | 'failed' | 'pending';
        taskId?: string;
        version?: string;
      }> = [];
      
      if (savedHistory) {
        try {
          history = JSON.parse(savedHistory);
        } catch (e) {
          console.error('Failed to load TUF history:', e);
        }
      }
      
      const responseData = response.data?.data;
      const taskId = responseData?.task_id;
      
      const newEntry = {
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        timestamp: responseData?.last_update || new Date().toISOString(),
        appName: appName,
        operation: 'unsign' as const,
        status: 'success' as const,
        taskId: taskId,
        version: version,
      };
      
      const updatedHistory = [newEntry, ...history].slice(0, 20); // Keep last 20 entries
      localStorage.setItem('tuf-history', JSON.stringify(updatedHistory));

      // Update the artifact's TufSigned status to false locally immediately
      const updatedArtifacts = formData.Artifacts.map((artifact, i) => 
        i === index ? { ...artifact, TufSigned: false } : artifact
      );
      
      // Mark this artifact as pending unsign confirmation
      pendingUnsignRef.current.add(index);
      
      setFormData(prev => ({
        ...prev,
        Artifacts: updatedArtifacts
      }));

      // Invalidate and refetch queries to get updated data from server
      // Add a delay to allow server to process the request and update artifacts
      setTimeout(async () => {
        await queryClient.invalidateQueries({ queryKey: ['apps'] });
        await queryClient.refetchQueries({ queryKey: ['apps'] });
      }, 2000);
      
      // Also refetch after a longer delay to catch status updates
      setTimeout(async () => {
        await queryClient.refetchQueries({ queryKey: ['apps'] });
        // Clear pending after final refetch
        setTimeout(() => {
          pendingUnsignRef.current.delete(index);
        }, 500);
      }, 5000);

      setUnsignSuccess(true);
      setTimeout(() => {
        setUnsignSuccess(false);
      }, 3000);
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      
      // Save failed operation to history
      const savedHistory = localStorage.getItem('tuf-history');
      let history: Array<{
        id: string;
        timestamp: string;
        appName: string;
        operation: 'generate' | 'bootstrap' | 'publish' | 'unsign';
        status: 'success' | 'failed' | 'pending';
        taskId?: string;
        version?: string;
      }> = [];
      
      if (savedHistory) {
        try {
          history = JSON.parse(savedHistory);
        } catch (e) {
          console.error('Failed to load TUF history:', e);
        }
      }
      
      const newEntry = {
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        appName: appName,
        operation: 'unsign' as const,
        status: 'failed' as const,
        version: version,
      };
      
      const updatedHistory = [newEntry, ...history].slice(0, 20); // Keep last 20 entries
      localStorage.setItem('tuf-history', JSON.stringify(updatedHistory));
      
      if (axiosError.response?.data) {
        setUnsignError({
          error: axiosError.response.data.error || 'Failed to unsign artifact',
          details: axiosError.response.data.details
        });
      } else {
        setUnsignError({
          error: 'Failed to unsign artifact',
          details: axiosError.message
        });
      }
    } finally {
      setIsUnsigning(false);
    }
  };

  return (
    <>
      <BaseModal
        title={`Edit version ${version}`}
        onClose={onClose}
        isLoading={isLoading}
        isSuccess={isSuccess}
        successMessage="Changes saved successfully!"
        error={error}
        setError={setError}
        className="w-[800px] max-h-[90vh] overflow-y-auto relative"
      >
        <div className="-mt-2 flex flex-wrap items-center gap-2 text-sm text-white/70">
          <span className="inline-flex items-center rounded-full border border-purple-300/45 bg-purple-500/30 px-2 py-0.5 text-xs font-semibold text-purple-100">
            {channel}
          </span>
          <span>{appName}</span>
        </div>

        <form onSubmit={handleSubmit} noValidate>
          <p className={SECTION}>Release flags</p>
          <div className="flex flex-wrap gap-2">
            <FlagCheckbox
              label="Published"
              tone="green"
              checked={formData.Published}
              onChange={(checked) => setFormData({ ...formData, Published: checked })}
            />
            <FlagCheckbox
              label="Critical"
              tone="red"
              checked={formData.Critical}
              onChange={(checked) => setFormData({ ...formData, Critical: checked })}
            />
            <FlagCheckbox
              label="Intermediate"
              tone="amber"
              checked={formData.Intermediate}
              onChange={(checked) => setFormData({ ...formData, Intermediate: checked })}
            />
          </div>

          <p className={SECTION}>
            Artifacts
            {tufStatus && (
              <span
                className={`${STATUS_BADGE} ${TUF_BADGE_STYLE[tufStatus].badge} normal-case tracking-normal`}
                title={TUF_BADGE_STYLE[tufStatus].hint}
              >
                <span className={`${STATUS_DOT} ${TUF_BADGE_STYLE[tufStatus].dot}`}></span>
                {TUF_BADGE_STYLE[tufStatus].label}
              </span>
            )}
          </p>

          {hasValidArtifacts ? (
            <>
              <div className="space-y-2">
                {formData.Artifacts.map((artifact, index) => (
                  <div key={index} className={ROW}>
                    <div className="flex min-w-0 items-center gap-3">
                      <span className={ROW_TILE}>
                        <i className={`${getPlatformIcon(artifact.platform)} text-white/90`}></i>
                      </span>
                      <div className="min-w-0">
                        <p className={ROW_TITLE}>{artifact.platform}</p>
                        <div className={ROW_META}>
                          <span>{artifact.arch}</span>
                          <span aria-hidden="true">·</span>
                          <span className="truncate">{artifact.package}</span>
                        </div>
                      </div>
                      {artifact.TufTaskID && (
                        <span
                          className={`${STATUS_BADGE} shrink-0 ${
                            artifact.TufSigned
                              ? 'text-green-300 border-green-500/40'
                              : 'text-red-300 border-red-500/45'
                          }`}
                        >
                          <i className="fas fa-shield-alt text-[11px]"></i>
                          {artifact.TufSigned ? 'signed' : 'unsigned'}
                        </span>
                      )}
                    </div>
                    <div className={ACTION_GROUP}>
                      <button
                        type="button"
                        onClick={() => handleDownload(artifact)}
                        className={`${ACTION_BUTTON} text-green-400 hover:bg-green-500/20`}
                        title="Download"
                        aria-label="Download"
                      >
                        <i className="fas fa-download"></i>
                      </button>
                      {artifact.TufSigned && (
                        <button
                          type="button"
                          onClick={() => handleUnsignArtifact(index)}
                          disabled={isUnsigning}
                          className={`${ACTION_BUTTON} text-amber-300 hover:bg-amber-500/25 disabled:cursor-not-allowed disabled:opacity-50`}
                          title="Unsign artifact from TUF"
                          aria-label="Unsign artifact from TUF"
                        >
                          <i className={`fas ${isUnsigning ? 'fa-spinner fa-spin' : 'fa-unlock'}`}></i>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleDeleteArtifact(index, artifact.platform, artifact.arch)}
                        className={`${ACTION_BUTTON} text-red-300 hover:bg-red-500/25`}
                        title="Delete"
                        aria-label="Delete"
                      >
                        <i className="fas fa-trash"></i>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
              {appData?.Tuf && tufStatus !== null && tufStatus !== 'all-signed' && (
                <button
                  type="button"
                  onClick={handleTufPublish}
                  disabled={isPublishingTuf}
                  className={`${BTN_WARNING} mt-2`}
                  title="Publish TUF artifacts"
                >
                  <i className={`fas ${isPublishingTuf ? 'fa-spinner fa-spin' : 'fa-shield-alt'}`}></i>
                  {isPublishingTuf
                    ? 'Signing…'
                    : `Sign ${unsignedCount} remaining ${unsignedCount === 1 ? 'artifact' : 'artifacts'} with TUF`}
                </button>
              )}
            </>
          ) : (
            <div className={NOTE_WARNING}>
              <i className="fas fa-exclamation-triangle"></i>
              This version has no artifacts yet — upload them below.
            </div>
          )}

          <p className={SECTION}>Add files</p>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            onChange={handleFileChange}
            className="hidden"
            id="file-upload"
          />
          <label
            htmlFor="file-upload"
            className={DROPZONE}
          >
            <i className="fas fa-plus"></i>
            Choose files to upload
          </label>

          {selectedFiles.length > 0 && (
            <div className="mt-2 space-y-2">
              {selectedFiles.map((file, index) => (
                <div key={index} className={ROW}>
                  <div className="flex min-w-0 items-center gap-3">
                    <span className={ROW_TILE}>
                      <i className="fas fa-file text-white/90"></i>
                    </span>
                    <div className="min-w-0">
                      <p className={ROW_TITLE}>{file.name}</p>
                      <div className={ROW_META}>
                        <span>{formatFileSize(file.size)}</span>
                      </div>
                    </div>
                  </div>
                  <div className={ACTION_GROUP}>
                    <button
                      type="button"
                      onClick={() => removeFile(index)}
                      className={`${ACTION_BUTTON} text-red-300 hover:bg-red-500/25`}
                      title="Remove file"
                      aria-label="Remove file"
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {selectedFiles.length > 0 && (
            <div className="mt-3 grid grid-cols-2 gap-3">
              {platforms.length > 0 && (
                <div>
                  <label className={FIELD_LABEL}>Platform</label>
                  <Dropdown
                    ariaLabel="Platform"
                    placeholder="Select platform"
                    value={platform}
                    onChange={(value) => handleOptionClick('platform', value)}
                    options={platforms.map((p) => ({
                      value: p.PlatformName,
                      label: p.PlatformName,
                      icon: getPlatformIcon(p.PlatformName),
                    }))}
                  />
                </div>
              )}
              {architectures.length > 0 && (
                <div>
                  <label className={FIELD_LABEL}>Architecture</label>
                  <Dropdown
                    ariaLabel="Architecture"
                    placeholder="Select architecture"
                    value={arch}
                    onChange={(value) => handleOptionClick('arch', value)}
                    options={architectures.map((a) => ({ value: a.ArchID, label: a.ArchID }))}
                  />
                </div>
              )}
              {showUpdaterDropdown && (
                <div className="col-span-2">
                  <label className={FIELD_LABEL}>
                    Updater
                    <span className="ml-2 font-normal text-white/50">
                      This platform has several enabled updaters — pick one if needed.
                    </span>
                  </label>
                  <Dropdown
                    ariaLabel="Updater"
                    placeholder="manual (default)"
                    value={updater}
                    onChange={(value) => handleOptionClick('updater', value)}
                    options={availableUpdaters.map((u) => ({ value: u.type, label: u.type }))}
                  />
                </div>
              )}
              {updater === 'tauri' && (
                <div className="col-span-2">
                  <label className={FIELD_LABEL}>Signature</label>
                  <input
                    type="text"
                    name="signature"
                    value={signature}
                    onChange={(e) => setSignature(e.target.value)}
                    className={FIELD_INPUT}
                    placeholder="Enter signature for Tauri updater"
                    required
                  />
                </div>
              )}
            </div>
          )}

          <p className={SECTION}>
            Changelog
            <span className={`${SEGMENTED_GROUP} normal-case tracking-normal`}>
              <button
                type="button"
                onClick={() => setIsPreview(false)}
                aria-pressed={!isPreview}
                className={segmentedButton(!isPreview)}
              >
                Edit
              </button>
              <button
                type="button"
                onClick={() => setIsPreview(true)}
                aria-pressed={isPreview}
                className={segmentedButton(isPreview, true)}
              >
                Preview
              </button>
            </span>
          </p>
          {isPreview ? (
            <div className={MARKDOWN_PREVIEW}>
              <ReactMarkdown>{formData.Changelog}</ReactMarkdown>
            </div>
          ) : (
            <textarea
              value={formData.Changelog}
              onChange={(e) => setFormData({ ...formData, Changelog: e.target.value })}
              className={`${FIELD_INPUT} min-h-[110px] font-mono text-sm`}
              placeholder="Enter changelog in Markdown format..."
            />
          )}

          <p className={SECTION}>Staged rollout</p>
          <RolloutSlider value={rollout} channel={channel} onChange={setRollout} />

          <div className="mt-8 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className={BTN_GHOST}
            >
              Cancel
            </button>
            <button
              type="submit"
              className={BTN_PRIMARY}
              disabled={Boolean(selectedFiles.length > 0 &&
                ((platforms.length > 0 && !platform) ||
                 (architectures.length > 0 && !arch) ||
                 (showUpdaterDropdown && updater === '')))}
            >
              Save changes
            </button>
          </div>
        </form>
      </BaseModal>

      {showDeleteConfirmation && artifactToDelete && (
        <DeleteArtifactConfirmationModal
          platform={artifactToDelete.platform}
          arch={artifactToDelete.arch}
          onClose={() => {
            setShowDeleteConfirmation(false);
            setArtifactToDelete(null);
            setDeleteError(null);
          }}
          onConfirm={confirmDeleteArtifact}
        />
      )}

      <ModalFeedback
        isSuccess={deleteSuccess}
        successMessage="Artifact deleted"
        error={deleteError}
        setError={setDeleteError}
      />
      <ModalFeedback
        isSuccess={unsignSuccess}
        successMessage="Artifact unsigned"
        error={unsignError}
        setError={setUnsignError}
      />
    </>
  );
}; 