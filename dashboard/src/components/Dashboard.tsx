import React from 'react';
import { useAppsQuery, AppVersion, AppListItem, ChangelogEntry, PaginatedResponse, BulkDeleteOutcome } from '@/hooks/use-query/useAppsQuery';
import { ActionIcons } from '@/components/ActionIcons';
import { EditVersionModal } from '@/components/modals/EditVersionModal';
import { DeleteConfirmationModal } from '@/components/modals/DeleteConfirmationModal';
import { DeleteVersionsConfirmationModal, SelectedVersion } from '@/components/modals/DeleteVersionsConfirmationModal';
import { DownloadArtifactsModal } from '@/components/modals/DownloadArtifactsModal';
import { EditAppModal } from '@/components/modals/EditAppModal';
import { DeleteAppConfirmationModal } from '@/components/modals/DeleteAppConfirmationModal';
import { CiUploadCommandModal } from '@/components/modals/CiUploadCommandModal';
import { useSearchParams } from 'react-router-dom';
import axiosInstance from '@/config/axios';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearch } from '@/hooks/useSearch.ts';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { useToast } from '@/hooks/useToast';
import ReactMarkdown from 'react-markdown';
import { getPlatformIcon } from '@/utils/platformIcon';
import { useAppDataQuery } from '@/hooks/use-query/useAppDataQuery';
import { AppLogo } from '@/components/common/AppLogo';
import { Dropdown } from '@/components/common/Dropdown';
import { DownloadTokensSection } from '@/components/DownloadTokensSection';
import '@/styles/cards.css';

import {
  BTN_DANGER,
  PLATFORM_CHIP,
  SECTION_LABEL,
  STATUS_BADGE,
  STATUS_DOT,
  TUF_BADGE_STYLE,
} from '@/components/common/ui';

// Fixed-height slots for the optional bits of the bottom block. Reserving the space
// costs a little emptiness on simple versions and buys every tile in a row the same
// baseline for its changelog and actions.
const TUF_SLOT = 'min-h-[41px]';
const CHANGELOG_SLOT = 'mt-3 min-h-[42px]';
const FOOTER_SLOT = 'mt-4 min-h-[40px]';

const SECTION = `${SECTION_LABEL} mt-5 mb-2`;

interface DashboardProps {
  selectedApp: string | null;
  onAppClick: (appName: string) => void;
  onChangelogClick: (version: string, changelog: ChangelogEntry[]) => void;
  onBackClick: () => void;
  refreshKey?: number;
  searchTerm: string;
}

interface VersionFilters {
  channel: string;
  published: boolean | null;
  critical: boolean | null;
  platform: string;
  arch: string;
}

interface ReportKeyItem {
  id: string;
  app_id: string;
  app_name: string;
  key_value: string;
  updated_at: string;
}

interface ReportKeysResponse {
  report_keys: ReportKeyItem[];
}

export const Dashboard: React.FC<DashboardProps> = ({
  selectedApp,
  onAppClick,
  onChangelogClick,
  onBackClick,
  refreshKey = 0,
  searchTerm
}) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const currentPage = parseInt(searchParams.get('page') || '1', 10);
  const queryClient = useQueryClient();
  const [filters, setFilters] = React.useState<VersionFilters>({
    channel: '',
    published: null,
    critical: null,
    platform: '',
    arch: ''
  });

  React.useEffect(() => {
    if (!selectedApp || typeof window === 'undefined') {
      return;
    }

    window.scrollTo({ top: 0, behavior: 'auto' });
  }, [selectedApp]);

  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();
  const { channels } = useChannelQuery();

  const { apps, updateApp, deleteApp, deleteVersions, fetchAllMatchingVersions, isLoading } = useAppsQuery(
    selectedApp || undefined, 
    currentPage, 
    refreshKey,
    filters
  );
  const [selectedVersion, setSelectedVersion] = React.useState<AppVersion | null>(null);
  const [showEditModal, setShowEditModal] = React.useState(false);
  const [showDeleteModal, setShowDeleteModal] = React.useState(false);
  const [showDownloadModal, setShowDownloadModal] = React.useState(false);
  const [expandedApps, setExpandedApps] = React.useState<Record<string, boolean>>({});
  const [showEditAppModal, setShowEditAppModal] = React.useState(false);
  const [showDeleteAppModal, setShowDeleteAppModal] = React.useState(false);
  const [selectedAppData, setSelectedAppData] = React.useState<AppListItem | null>(null);
  const [publishingTuf, setPublishingTuf] = React.useState<Record<string, boolean>>({});
  const [openArtifactsPopoverId, setOpenArtifactsPopoverId] = React.useState<string | null>(null);
  const [hoveredArtifactsPopoverId, setHoveredArtifactsPopoverId] = React.useState<string | null>(null);
  const [suppressHoverArtifactsPopoverId, setSuppressHoverArtifactsPopoverId] = React.useState<string | null>(null);
  const [isRegeneratingReportKey, setIsRegeneratingReportKey] = React.useState(false);
  const [selectionMode, setSelectionMode] = React.useState(false);
  const [selection, setSelection] = React.useState<Map<string, SelectedVersion>>(new Map());
  const [isSelectingAll, setIsSelectingAll] = React.useState(false);
  const [showBulkDeleteModal, setShowBulkDeleteModal] = React.useState(false);
  const [showCiCommandModal, setShowCiCommandModal] = React.useState(false);
  const { toastSuccess, toastError } = useToast();

  const appList = React.useMemo(() => {
    if (!apps) return [];
    if (Array.isArray(apps)) {
      return apps as AppListItem[];
    }
    if ('items' in apps) {
      return (apps as PaginatedResponse<AppVersion>).items;
    }
    return [];
  }, [apps]);

  const paginatedVersions = React.useMemo(() => {
    if (!apps) return { items: [], total: 0, page: 1, limit: 9 };
    if ('items' in apps) {
      return apps as PaginatedResponse<AppVersion>;
    }
    return { items: [], total: 0, page: 1, limit: 9 };
  }, [apps]);

  const appVersions = paginatedVersions.items || [];

  const filteredAppList = useSearch(appList, searchTerm) as AppListItem[];

  const { data: appData } = useAppDataQuery(selectedApp);

  const { data: reportKeysData, isLoading: isReportKeysLoading } = useQuery({
    queryKey: ['reportKeys', selectedApp],
    queryFn: async () => {
      const response = await axiosInstance.get('/report-keys/list');
      return response.data as ReportKeysResponse;
    },
    enabled: !!selectedApp,
  });

  const reportKeyForApp = React.useMemo(() => {
    const keys = reportKeysData?.report_keys;
    if (!keys || keys.length === 0 || !selectedApp) {
      return null;
    }

    const matchedKeys = keys
      .filter((key) => key.app_id === appData?.ID || key.app_name === selectedApp)
      .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

    return matchedKeys[0] || null;
  }, [reportKeysData, appData?.ID, selectedApp]);

  const handleCopyReportKey = async () => {
    if (!reportKeyForApp?.key_value) {
      return;
    }

    try {
      await navigator.clipboard.writeText(reportKeyForApp.key_value);
      toastSuccess('Report key copied');
    } catch (error) {
      toastError('Failed to copy report key');
    }
  };

  const handleRegenerateReportKey = async () => {
    if (!appData?.ID || isRegeneratingReportKey) {
      return;
    }

    const confirmed = window.confirm(
      'Are you sure you want to regenerate the report key? This can affect clients and prevent them from sending reports.'
    );
    if (!confirmed) {
      return;
    }

    setIsRegeneratingReportKey(true);

    try {
      await axiosInstance.post('/report-keys/regenerate', {
        app_id: appData.ID,
      });

      await queryClient.invalidateQueries({ queryKey: ['reportKeys', selectedApp] });
      await queryClient.refetchQueries({ queryKey: ['reportKeys', selectedApp] });
      toastSuccess('Report key regenerated');
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to regenerate report key';
      toastError(errorMessage);
    } finally {
      setIsRegeneratingReportKey(false);
    }
  };

  const handlePageChange = (page: number) => {
    setSearchParams({ page: page.toString() });
  };

  const handleDownload = (app: AppVersion) => {
    if (app.Artifacts.length === 1) {
      // First try to fetch the link with authentication
      axiosInstance.get(app.Artifacts[0].link)
        .then(response => {
          // Check if the response is JSON with a download_url
          if (response.data && typeof response.data === 'object' && 'download_url' in response.data) {
            // If it's a JSON with download_url, use that URL
            window.open(response.data.download_url, '_blank', 'noopener,noreferrer');
          } else {
            // Otherwise, it's a direct link to a file, use it directly
            window.open(app.Artifacts[0].link, '_blank', 'noopener,noreferrer');
          }
        })
        .catch((error) => {
          if (error?.response?.status === 404) {
            toastError('Download is not available');
            return;
          }
          // If there's an error (like 401), it might be a direct link to a public file
          // In that case, just open the link directly
          window.open(app.Artifacts[0].link, '_blank', 'noopener,noreferrer');
        });
    } else {
      setSelectedVersion(app);
      setShowDownloadModal(true);
    }
  };

  const handleEdit = (app: AppVersion) => {
    setSelectedVersion(app);
    setShowEditModal(true);
  };

  const handleDelete = (app: AppVersion) => {
    setSelectedVersion(app);
    setShowDeleteModal(true);
  };

  const handleEditApp = (e: React.MouseEvent, app: AppListItem) => {
    e.stopPropagation();
    setSelectedAppData(app);
    setShowEditAppModal(true);
  };

  const handleDeleteApp = (e: React.MouseEvent, app: AppListItem) => {
    e.stopPropagation();
    setSelectedAppData(app);
    setShowDeleteAppModal(true);
  };

  const handleEditSave = async (data: {
    Published: boolean;
    Critical: boolean;
    Intermediate: boolean;
    Changelog: string;
    Platform?: string;
    Arch?: string;
    Files?: File[];
    app_name: string;
    version: string;
    channel: string;
    rollout?: number;
  }) => {
    if (selectedVersion) {
      await updateApp(selectedVersion.ID, data);
      setShowEditModal(false);
      setSelectedVersion(null);
      queryClient.invalidateQueries({ queryKey: ['apps'] });
      // Force a refetch to ensure we have the latest data
      await queryClient.refetchQueries({ queryKey: ['apps'] });
    }
  };

  const handleDeleteConfirm = async () => {
    if (selectedVersion) {
      await deleteApp(selectedVersion.ID);
      setShowDeleteModal(false);
      setSelectedVersion(null);
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    }
  };

  const handleEditAppSave = async () => {
    setShowEditAppModal(false);
    setSelectedAppData(null);
    queryClient.invalidateQueries({ queryKey: ['apps'] });
    queryClient.invalidateQueries({ queryKey: ['appData'] });
  };

  // Selection is page-local on purpose: what is selected must stay on screen, so
  // anything that changes the visible set drops it. "Select all matching" is the
  // one deliberate exception and it announces its own count.
  React.useEffect(() => {
    setSelectionMode(false);
    setSelection(new Map());
  }, [selectedApp, currentPage, filters]);

  const toggleSelection = (app: AppVersion) => {
    setSelection(prev => {
      const next = new Map(prev);
      if (next.has(app.ID)) {
        next.delete(app.ID);
      } else {
        next.set(app.ID, { id: app.ID, version: app.Version, channel: app.Channel });
      }
      return next;
    });
  };

  const handleSelectPage = () => {
    setSelection(new Map(
      appVersions.map(app => [app.ID, { id: app.ID, version: app.Version, channel: app.Channel }])
    ));
  };

  const handleSelectAllMatching = async () => {
    setIsSelectingAll(true);
    try {
      const all = await fetchAllMatchingVersions(paginatedVersions.total);
      setSelection(new Map(
        all.map(app => [app.ID, { id: app.ID, version: app.Version, channel: app.Channel }])
      ));
    } catch {
      toastError('Failed to load all matching versions');
    } finally {
      setIsSelectingAll(false);
    }
  };

  const handleBulkDeleteConfirm = async (
    ids: string[],
    onProgress: (done: number, total: number) => void,
  ): Promise<BulkDeleteOutcome> => {
    const outcome = await deleteVersions(ids, onProgress);

    setSelection(prev => {
      const next = new Map(prev);
      outcome.deletedIds.forEach(id => next.delete(id));
      return next;
    });

    await queryClient.invalidateQueries({ queryKey: ['apps'] });
    await queryClient.refetchQueries({ queryKey: ['apps'] });

    if (outcome.deletedIds.length > 0) {
      toastSuccess(`Deleted ${outcome.deletedIds.length} version${outcome.deletedIds.length === 1 ? '' : 's'}`);
    }
    if (outcome.error) {
      toastError(outcome.error);
    } else {
      setSelectionMode(false);
    }

    return outcome;
  };

  const handleDeleteAppConfirm = async () => {
    if (selectedAppData) {
      try {
        await axiosInstance.delete(`/app/delete?id=${selectedAppData.ID}`);
        setShowDeleteAppModal(false);
        setSelectedAppData(null);
        queryClient.invalidateQueries({ queryKey: ['apps'] });
      } catch (error) {
        console.error('Error deleting app:', error);
        throw error;
      }
    }
  };

  const totalPages = Math.ceil((paginatedVersions?.total || 0) / 9);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const day = date.getDate();
    const month = date.toLocaleString('en-US', { month: 'long' });
    const year = date.getFullYear();
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${day} ${month} ${year}, ${hours}:${minutes}`;
  };

  const handleTufPublish = async (e: React.MouseEvent, version: AppVersion) => {
    e.stopPropagation();
    
    if (!appData?.ID) {
      toastError('App ID not found');
      return;
    }

    const versionId = version.ID;
    setPublishingTuf(prev => ({ ...prev, [versionId]: true }));

    try {
      const response = await axiosInstance.post('/tuf/v1/artifacts/publish', {
        app_id: appData.ID,
        version: version.Version
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
          appName: selectedApp || appData.AppName,
          operation: 'publish' as const,
          status: 'pending' as const,
          taskId: taskId,
        };
        
        const updatedHistory = [newEntry, ...history].slice(0, 20); // Keep last 20 entries
        localStorage.setItem('tuf-history', JSON.stringify(updatedHistory));
      }
      
      toastSuccess(`TUF artifacts publishing successfully started for version ${version.Version}`);
      
      // Invalidate and refetch queries with correct parameters
      // Add a delay to allow server to process the request and update artifacts
      setTimeout(async () => {
        // Invalidate all apps queries
        queryClient.invalidateQueries({ queryKey: ['apps'] });
        queryClient.invalidateQueries({ queryKey: ['appData', selectedApp] });
        
        // Refetch with exact query key to ensure we get updated data
        await queryClient.refetchQueries({ 
          queryKey: ['apps', selectedApp, currentPage, refreshKey, filters] 
        });
        await queryClient.refetchQueries({ queryKey: ['appData', selectedApp] });
      }, 2000);
      
      // Also refetch after a longer delay to catch status updates (when signing completes)
      setTimeout(async () => {
        await queryClient.refetchQueries({ 
          queryKey: ['apps', selectedApp, currentPage, refreshKey, filters] 
        });
      }, 5000);
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to publish TUF artifacts';
      toastError(errorMessage);
    } finally {
      setPublishingTuf(prev => ({ ...prev, [versionId]: false }));
    }
  };

  const getTufSignStatus = (version: AppVersion): 'all-signed' | 'partial' | 'none' | null => {
    if (!appData?.Tuf) {
      return null;
    }
    
    // Consider artifacts that have TufTaskID (not null/undefined) OR have TufTaskID === null and TufSigned === false
    const tufArtifacts = version.Artifacts.filter(artifact => {
      // Feeds are the updater's index, not a TUF target: the server never signs them,
      // so counting them would leave every version stuck on 'partial'.
      if (artifact.IsFeed) {
        return false;
      }
      // Include artifacts with TufTaskID (not null/undefined)
      if (artifact.TufTaskID) {
        return true;
      }
      // Also include artifacts with TufTaskID === null and TufSigned === false (not signed)
      if (artifact.TufTaskID === null && artifact.TufSigned === false) {
        return true;
      }
      return false;
    });
    
    // If TUF is enabled but no artifacts match the criteria, check if there are any artifacts at all
    if (tufArtifacts.length === 0) {
      if (version.Artifacts.some(artifact => !artifact.IsFeed)) {
        return 'none';
      } else {
        return null;
      }
    }
    
    // Count signed artifacts (TufSigned === true)
    const signedCount = tufArtifacts.filter(artifact => artifact.TufSigned === true).length;
    
    if (signedCount === tufArtifacts.length) {
      return 'all-signed';
    }
    if (signedCount > 0) {
      return 'partial';
    }
    return 'none';
  };

  const getArtifactSummary = (artifacts: AppVersion['Artifacts']) => {
    const groupedByPlatform = artifacts.reduce<Record<string, { count: number; label: string; unsigned: number }>>((acc, artifact) => {
      const rawPlatform = artifact.platform?.trim() || 'N/A';
      const key = rawPlatform.toLowerCase();
      if (!acc[key]) {
        acc[key] = { count: 0, label: rawPlatform, unsigned: 0 };
      }
      acc[key].count += 1;
      if (artifact.TufSigned === false && !artifact.IsFeed) {
        acc[key].unsigned += 1;
      }
      return acc;
    }, {});

    const sortedGroups = Object.entries(groupedByPlatform)
      .sort((a, b) => b[1].count - a[1].count || a[1].label.localeCompare(b[1].label))
      .map(([, value]) => ({
        count: value.count,
        label: value.label,
        unsigned: value.unsigned,
      }));

    const visibleGroups = sortedGroups.slice(0, 3);
    const hiddenGroupsCount = Math.max(sortedGroups.length - visibleGroups.length, 0);

    return {
      visibleSummary: visibleGroups.map(item => `${item.label}(${item.count})`).join(' '),
      visibleGroups,
      hiddenGroupsCount,
      details: artifacts.map(artifact => {
        const platform = artifact.platform?.trim() || 'N/A';
        const arch = artifact.arch?.trim() || 'N/A';
        const pkg = artifact.package?.trim() || 'N/A';
        return `${platform}/${arch} - ${pkg}`;
      }),
    };
  };

  if (selectedApp) {
    return (
      <div className="mt-8">
        <div className="flex flex-col lg:flex-row lg:items-center gap-4 mb-6">
        <button
          onClick={onBackClick}
          className="self-start px-4 py-2 bg-theme-card text-theme-primary rounded-lg hover:bg-theme-card-hover transition-colors flex items-center gap-2"
        >
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
          >
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
          Back
        </button>

        <button
          onClick={() => setShowCiCommandModal(true)}
          className="self-start px-4 py-2 bg-theme-card text-theme-primary rounded-lg hover:bg-theme-card-hover transition-colors flex items-center gap-2"
        >
          <i className="fas fa-terminal"></i>
          CI command
        </button>

          {appData?.Reports && (
            <div
              className="relative group w-full lg:w-auto lg:ml-auto lg:min-w-[420px] h-12 rounded-lg border border-blue-400/30 bg-blue-500/10 px-3 flex items-center gap-2"
            >
              <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-blue-200 flex-shrink-0">
                <svg
                  className="w-3.5 h-3.5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M7 8h10M7 12h6m-6 4h10M5 21h14a2 2 0 002-2V7l-5-5H5a2 2 0 00-2 2v15a2 2 0 002 2z"
                  />
                </svg>
                Report key
              </span>

              {isReportKeysLoading ? (
                <p className="text-xs text-white/70 truncate">Loading...</p>
              ) : reportKeyForApp?.key_value ? (
                <>
                  <p
                    className="font-mono text-xs text-white/95 overflow-x-auto whitespace-nowrap flex-1 min-w-0"
                  >
                    {reportKeyForApp.key_value}
                  </p>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <button
                      type="button"
                      onClick={handleCopyReportKey}
                      className="p-1.5 rounded-md bg-theme-card text-theme-primary hover:bg-theme-card-hover transition-colors"
                      aria-label="Copy report key"
                      title="Copy report key"
                    >
                      <svg
                        className="w-3.5 h-3.5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                        />
                      </svg>
                    </button>
                    <button
                      type="button"
                      onClick={handleRegenerateReportKey}
                      disabled={isRegeneratingReportKey}
                      className="p-1.5 rounded-md bg-red-500/20 text-red-300 border border-red-400/30 hover:bg-red-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      aria-label="Regenerate report key"
                      title={isRegeneratingReportKey ? 'Regenerating...' : 'Regenerate report key'}
                    >
                      <svg
                        className={`w-3.5 h-3.5 ${isRegeneratingReportKey ? 'animate-spin' : ''}`}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M21 12a9 9 0 10-2.64 6.36M21 3v6h-6"
                        />
                      </svg>
                    </button>
                  </div>
                </>
              ) : (
                <p className="text-xs text-white/70 truncate">Not available yet</p>
              )}

              {reportKeyForApp?.key_value && (
                <div className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 -translate-x-1/2 whitespace-nowrap rounded-md border border-theme-card-hover bg-gray-900 px-2 py-1 text-[11px] text-theme-primary opacity-0 shadow-lg transition-opacity duration-150 group-hover:opacity-100">
                  Updated: {formatDate(reportKeyForApp.updated_at)}
                </div>
              )}
            </div>
          )}
        </div>

        {appData?.Private && appData.ID && (
          <DownloadTokensSection appId={appData.ID} downloadMode={appData.DownloadMode} formatDate={formatDate} />
        )}

        {/* Filters Section */}
        <div className="mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
            <Dropdown
              ariaLabel="Channel"
              placeholder="All channels"
              value={filters.channel}
              onChange={(channel) => setFilters(prev => ({ ...prev, channel }))}
              options={[
                { value: '', label: 'All channels' },
                ...channels.map(channel => ({ value: channel.ChannelName, label: channel.ChannelName })),
              ]}
            />

            <Dropdown
              ariaLabel="Platform"
              placeholder="All platforms"
              value={filters.platform}
              onChange={(platform) => setFilters(prev => ({ ...prev, platform }))}
              options={[
                { value: '', label: 'All platforms' },
                ...platforms.map(platform => ({
                  value: platform.PlatformName,
                  label: platform.PlatformName,
                  icon: getPlatformIcon(platform.PlatformName),
                })),
              ]}
            />

            <Dropdown
              ariaLabel="Architecture"
              placeholder="All architectures"
              value={filters.arch}
              onChange={(arch) => setFilters(prev => ({ ...prev, arch }))}
              options={[
                { value: '', label: 'All architectures' },
                ...architectures.map(arch => ({ value: arch.ArchID, label: arch.ArchID })),
              ]}
            />

            <Dropdown<boolean | null>
              ariaLabel="Publication status"
              placeholder="Publication status"
              value={filters.published}
              onChange={(published) => setFilters(prev => ({ ...prev, published }))}
              options={[
                { value: null, label: 'Any publication status' },
                { value: true, label: 'Published' },
                { value: false, label: 'Not published' },
              ]}
            />

            <Dropdown<boolean | null>
              ariaLabel="Critical status"
              placeholder="Critical status"
              value={filters.critical}
              onChange={(critical) => setFilters(prev => ({ ...prev, critical }))}
              options={[
                { value: null, label: 'Any critical status' },
                { value: true, label: 'Critical' },
                { value: false, label: 'Not critical' },
              ]}
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
          {appVersions.length > 0 && (
            <button
              onClick={() => {
                setSelectionMode(prev => !prev);
                setSelection(new Map());
              }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors text-theme-primary ${
                selectionMode ? 'bg-theme-card-hover' : 'bg-theme-card hover:bg-theme-card-hover'
              }`}
            >
              <i className={`fas ${selectionMode ? 'fa-times' : 'fa-check-square'}`}></i>
              {selectionMode ? 'Cancel selection' : 'Select'}
            </button>
          )}

          {/* Reset Filters Button */}
          {(filters.channel || filters.platform || filters.arch || filters.published !== null || filters.critical !== null) && (
            <button
              onClick={() => setFilters({
                channel: '',
                published: null,
                critical: null,
                platform: '',
                arch: ''
              })}
              className="flex items-center gap-2 px-4 py-2 bg-theme-card hover:bg-theme-card-hover text-theme-primary rounded-lg transition-colors"
            >
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
              >
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
              Reset Filters
            </button>
          )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {isLoading ? (
            <div className="col-span-full flex justify-center items-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
            </div>
          ) : appVersions.length === 0 ? (
            <div className="col-span-full text-center text-theme-primary text-xl">
              No versions have been uploaded yet.
            </div>
          ) : (
            appVersions.map((app) => {
              const tufStatus = getTufSignStatus(app);
              const isDangerZone = app.Published && tufStatus !== null && tufStatus !== 'all-signed';
              const isIncompleteRollout =
                app.Published && app.RolloutPercent != null && app.RolloutPercent < 100;
              const artifactSummary = getArtifactSummary(app.Artifacts);
              const isSelected = selection.has(app.ID);

              return (
              <div
                key={app.ID}
                onClick={selectionMode ? () => toggleSelection(app) : undefined}
                className={`sharedCard backdrop-blur-lg rounded-lg p-6 text-theme-primary transition-all relative ${
                  isDangerZone
                    ? 'border-2 border-red-500'
                    : isIncompleteRollout
                    ? 'border-2 border-amber-500 bg-theme-card hover:bg-theme-card-hover'
                    : 'bg-theme-card hover:bg-theme-card-hover'
                } ${selectionMode ? 'cursor-pointer' : ''} ${
                  isSelected ? 'ring-2 ring-purple-400' : ''
                }`}
                style={{
                  ['--card-color' as any]: isDangerZone ? '#EF4444' : isIncompleteRollout ? '#F59E0B' : '#8B5CF6',
                  ...(isDangerZone ? {
                    backgroundColor: 'rgba(239, 68, 68, 0.25)',
                    boxShadow: '0 10px 25px -5px rgba(239, 68, 68, 0.5), 0 0 0 1px rgba(239, 68, 68, 0.3)',
                    animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite'
                  } : isIncompleteRollout ? {
                    animation: 'glowAmber 2.4s ease-in-out infinite'
                  } : {})
                }}
                onMouseEnter={(e) => {
                  if (isDangerZone) {
                    (e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(239, 68, 68, 0.35)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (isDangerZone) {
                    (e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(239, 68, 68, 0.25)';
                  }
                }}
              >
                <div className={`flex items-center mb-4 min-w-0 w-full ${selectionMode ? 'justify-start' : 'justify-end'}`}>
                  <div className="flex gap-2 flex-shrink-0 items-center">
                    {selectionMode ? (
                      <label
                        className="flex items-center gap-2 cursor-pointer text-sm font-semibold text-theme-primary"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelection(app)}
                          className="h-4 w-4 cursor-pointer accent-purple-500"
                        />
                        {isSelected ? 'Selected' : 'Select'}
                      </label>
                    ) : (
                      <ActionIcons
                        onDownload={() => handleDownload(app)}
                        onEdit={() => handleEdit(app)}
                        onDelete={() => handleDelete(app)}
                        showDownload={app.Artifacts.length === 1 ? !!app.Artifacts[0].link : true}
                        artifactLink={app.Artifacts.length === 1 ? app.Artifacts[0].link : undefined}
                      />
                    )}
                  </div>
                </div>
                <div className="sharedCardContent relative flex w-full min-w-0 flex-col">
                  <h3
                    className="text-2xl font-extrabold tracking-tight text-theme-primary"
                    title={`Version ${app.Version}`}
                  >
                    {app.Version}
                  </h3>
                  <p className="mt-1 mb-6 text-sm text-white/70">
                    <span className="mr-2 inline-flex items-center rounded-full border border-purple-300/45 bg-purple-500/30 px-2 py-0.5 text-xs font-semibold text-purple-100">
                      {app.Channel}
                    </span>
                    {formatDate(app.Updated_at)}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <span className={`${STATUS_BADGE} ${
                      app.Published
                        ? 'text-green-300 border-green-500/40'
                        : 'text-slate-200 border-slate-400/40'
                    }`}>
                      <span className={`${STATUS_DOT} ${app.Published ? 'bg-green-500' : 'bg-slate-400'}`}></span>
                      {app.Published ? 'Published' : 'Not published'}
                    </span>
                    {app.Critical && (
                      <span className={`${STATUS_BADGE} text-red-300 border-red-500/45`}>
                        <span className={`${STATUS_DOT} bg-red-500`}></span>
                        Critical
                      </span>
                    )}
                    {app.Intermediate && (
                      <span className={`${STATUS_BADGE} text-amber-300 border-amber-500/45`}>
                        <span className={`${STATUS_DOT} bg-amber-500`}></span>
                        Intermediate
                      </span>
                    )}
                    {tufStatus && (
                      <span
                        className={`${STATUS_BADGE} ${TUF_BADGE_STYLE[tufStatus].badge}`}
                        title={TUF_BADGE_STYLE[tufStatus].hint}
                      >
                        <span className={`${STATUS_DOT} ${TUF_BADGE_STYLE[tufStatus].dot}`}></span>
                        {TUF_BADGE_STYLE[tufStatus].label}
                      </span>
                    )}
                    {isIncompleteRollout && (
                      <span
                        className={`${STATUS_BADGE} text-blue-300 border-blue-500/45`}
                        title="Staged rollout is not fully deployed"
                      >
                        <span className={`${STATUS_DOT} bg-blue-500`}></span>
                        Rollout {app.RolloutPercent}%
                      </span>
                    )}
                  </div>
                  {app.Artifacts.length > 0 && (
                    <>
                    <p className={SECTION}>Artifacts</p>
                    <div
                      className="relative group w-full min-w-0"
                      onMouseEnter={() => {
                        setHoveredArtifactsPopoverId(app.ID);
                      }}
                      onMouseLeave={() => {
                        setHoveredArtifactsPopoverId(prev => (prev === app.ID ? null : prev));
                        setSuppressHoverArtifactsPopoverId(prev => (prev === app.ID ? null : prev));
                      }}
                    >
                      <button
                        type="button"
                        className="flex w-full min-w-0 max-w-full flex-wrap gap-2 text-left"
                        title={`Artifacts: ${artifactSummary.visibleSummary}${artifactSummary.hiddenGroupsCount > 0 ? ` +${artifactSummary.hiddenGroupsCount}` : ''}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpenArtifactsPopoverId(prev => {
                            const isClosing = prev === app.ID;
                            if (isClosing) {
                              setSuppressHoverArtifactsPopoverId(app.ID);
                              return null;
                            }
                            setSuppressHoverArtifactsPopoverId(null);
                            return app.ID;
                          });
                        }}
                      >
                        {artifactSummary.visibleGroups.map(group => (
                          <span key={group.label} className={PLATFORM_CHIP}>
                            <i className={`${getPlatformIcon(group.label)} opacity-90`}></i>
                            {group.label}
                            <b className="font-bold tabular-nums">{group.count}</b>
                            {tufStatus && group.unsigned > 0 && (
                              <i
                                className="fas fa-shield-alt text-[11px] text-amber-300"
                                title={`${group.unsigned} not signed`}
                              ></i>
                            )}
                          </span>
                        ))}
                        {artifactSummary.hiddenGroupsCount > 0 && (
                          <span className={PLATFORM_CHIP}>+{artifactSummary.hiddenGroupsCount}</span>
                        )}
                      </button>
                      <div
                        className={`absolute left-0 right-0 bottom-full z-20 mb-2 rounded-lg border border-theme-card-hover bg-gray-900 p-3 shadow-xl transition-opacity duration-150 max-h-44 overflow-hidden flex flex-col ${
                          openArtifactsPopoverId === app.ID ||
                          (hoveredArtifactsPopoverId === app.ID && suppressHoverArtifactsPopoverId !== app.ID)
                            ? 'opacity-100 pointer-events-auto'
                            : 'opacity-0 pointer-events-none'
                        }`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpenArtifactsPopoverId(null);
                          setSuppressHoverArtifactsPopoverId(app.ID);
                        }}
                      >
                        <p className="mb-2 text-xs font-semibold text-theme-primary">
                          Artifact details
                        </p>
                        <div className="overflow-y-auto pr-1 flex-1 min-h-0">
                          {artifactSummary.details.map((detail, index) => (
                            <p key={`${app.ID}-artifact-${index}`} className="text-xs text-white/80 break-all mb-1 last:mb-0">
                              {detail}
                            </p>
                          ))}
                        </div>
                      </div>
                    </div>
                    </>
                  )}
                  {/* Anchored to the bottom of the tile: the grid stretches every card to the
                      tallest in its row, so without this the changelog and actions land at a
                      different height in each neighbour. Each slot keeps its height whether or
                      not its content exists, so only the gap above this block varies. */}
                  <div className="mt-auto pt-4">
                  <div className={TUF_SLOT}>
                    {tufStatus && tufStatus !== 'all-signed' && (
                      <button
                        onClick={(e) => handleTufPublish(e, app)}
                        disabled={publishingTuf[app.ID]}
                        className="flex w-full items-center justify-center gap-2 rounded-lg border border-amber-500/55 bg-violet-950/50 px-3 py-2 text-[13px] font-bold text-amber-300 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                        title="Publish TUF artifacts"
                      >
                        <i className={`fas ${publishingTuf[app.ID] ? 'fa-spinner fa-spin' : 'fa-shield-alt'}`}></i>
                        {publishingTuf[app.ID] ? 'Signing…' : 'Sign remaining artifacts with TUF'}
                      </button>
                    )}
                  </div>
                  <div className={`${CHANGELOG_SLOT} border-l-2 border-white/20 pl-3`}>
                    {app.Changelog && app.Changelog.length > 0 && app.Changelog[0].Changes ? (
                      <div className="text-sm text-white/80 line-clamp-2 prose prose-sm prose-invert max-w-none">
                        <ReactMarkdown
                          components={{
                            p: ({ children }) => <p className="m-0">{children}</p>,
                            ul: ({ children }) => <ul className="m-0 pl-4">{children}</ul>,
                            ol: ({ children }) => <ol className="m-0 pl-4">{children}</ol>,
                            li: ({ children }) => <li className="m-0">{children}</li>,
                            strong: ({ children }) => <strong className="font-semibold">{children}</strong>,
                            em: ({ children }) => <em className="italic">{children}</em>,
                            code: ({ children }) => <code className="bg-theme-input px-1 rounded text-xs">{children}</code>,
                            h1: ({ children }) => <h1 className="text-base font-bold m-0">{children}</h1>,
                            h2: ({ children }) => <h2 className="text-sm font-bold m-0">{children}</h2>,
                            h3: ({ children }) => <h3 className="text-sm font-semibold m-0">{children}</h3>,
                          }}
                        >
                          {app.Changelog[0].Changes}
                        </ReactMarkdown>
                      </div>
                    ) : (
                      <p className="text-sm text-white/60 italic">
                        Changelog not provided
                      </p>
                    )}
                  </div>
                  <div className={FOOTER_SLOT}>
                    {app.Changelog && app.Changelog.length > 0 && app.Changelog[0].Changes && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onChangelogClick(app.Version, app.Changelog);
                        }}
                        className="px-4 py-2 bg-theme-card text-theme-primary rounded-lg hover:bg-theme-card-hover transition-colors flex items-center gap-2"
                      >
                        View full changelog
                      </button>
                    )}
                  </div>
                  </div>
                </div>
              </div>
              );
            })
          )}
        </div>

        {selectionMode && (
          <div className="sticky bottom-4 z-30 mt-6 flex flex-wrap items-center gap-3 rounded-lg border border-white/20 bg-violet-950/80 px-4 py-3 backdrop-blur-lg">
            <span className="font-semibold text-theme-primary">
              {selection.size} selected
            </span>

            <button
              onClick={handleSelectPage}
              className="rounded-lg border border-white/25 px-3 py-1.5 text-sm font-semibold text-theme-primary transition-colors hover:bg-white/10"
            >
              Select all on page
            </button>

            {paginatedVersions.total > appVersions.length && (
              <button
                onClick={handleSelectAllMatching}
                disabled={isSelectingAll}
                className="rounded-lg border border-white/25 px-3 py-1.5 text-sm font-semibold text-theme-primary transition-colors hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSelectingAll ? 'Loading...' : `Select all ${paginatedVersions.total} matching filters`}
              </button>
            )}

            <button
              onClick={() => setSelection(new Map())}
              disabled={selection.size === 0}
              className="rounded-lg border border-white/25 px-3 py-1.5 text-sm font-semibold text-theme-primary transition-colors hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Clear
            </button>

            <button
              onClick={() => setShowBulkDeleteModal(true)}
              disabled={selection.size === 0}
              className={`ml-auto ${BTN_DANGER}`}
            >
              Delete {selection.size} version{selection.size === 1 ? '' : 's'}
            </button>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex justify-center gap-2 mt-8">
            <button
              onClick={() => handlePageChange(1)}
              disabled={currentPage === 1}
              className="px-4 py-2 rounded-lg bg-theme-card text-theme-primary hover:bg-theme-card-hover disabled:opacity-50 disabled:cursor-not-allowed"
              title="First page"
            >
              <i className="fas fa-angle-double-left"></i>
            </button>
            <button
              onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="px-4 py-2 rounded-lg bg-theme-card text-theme-primary hover:bg-theme-card-hover disabled:opacity-50 disabled:cursor-not-allowed"
              title="Previous page"
            >
              <i className="fas fa-angle-left"></i>
            </button>
            <span className="px-4 py-2 text-theme-primary">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => handlePageChange(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="px-4 py-2 rounded-lg bg-theme-card text-theme-primary hover:bg-theme-card-hover disabled:opacity-50 disabled:cursor-not-allowed"
              title="Next page"
            >
              <i className="fas fa-angle-right"></i>
            </button>
            <button
              onClick={() => handlePageChange(totalPages)}
              disabled={currentPage === totalPages}
              className="px-4 py-2 rounded-lg bg-theme-card text-theme-primary hover:bg-theme-card-hover disabled:opacity-50 disabled:cursor-not-allowed"
              title="Last page"
            >
              <i className="fas fa-angle-double-right"></i>
            </button>
          </div>
        )}

        {showEditModal && selectedVersion && (
          <EditVersionModal
            appName={selectedApp}
            version={selectedVersion.Version}
            channel={selectedVersion.Channel}
            currentData={{
              ID: selectedVersion.ID,
              Published: selectedVersion.Published,
              Critical: selectedVersion.Critical,
              Intermediate: selectedVersion.Intermediate,
              RolloutPercent: selectedVersion.RolloutPercent,
              Changelog: selectedVersion.Changelog[0]?.Changes || '',
              Artifacts: selectedVersion.Artifacts
            }}
            onClose={() => {
              setShowEditModal(false);
              setSelectedVersion(null);
            }}
            onSave={handleEditSave}
          />
        )}

        {showDeleteModal && selectedVersion && (
          <DeleteConfirmationModal
            version={`${selectedVersion.Version}`}
            onClose={() => {
              setShowDeleteModal(false);
              setSelectedVersion(null);
            }}
            onConfirm={handleDeleteConfirm}
          />
        )}

        {showBulkDeleteModal && selectedApp && (
          <DeleteVersionsConfirmationModal
            appName={selectedApp}
            versions={[...selection.values()]}
            onClose={() => setShowBulkDeleteModal(false)}
            onConfirm={handleBulkDeleteConfirm}
          />
        )}

        {showDownloadModal && selectedVersion && (
          <DownloadArtifactsModal
            artifacts={selectedVersion.Artifacts}
            onClose={() => {
              setShowDownloadModal(false);
              setSelectedVersion(null);
            }}
          />
        )}

        {showCiCommandModal && (
          <CiUploadCommandModal
            appName={selectedApp}
            isTuf={Boolean(appData?.Tuf)}
            isPrivate={Boolean(appData?.Private)}
            onClose={() => setShowCiCommandModal(false)}
          />
        )}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-8">
      {isLoading ? (
        <div className="col-span-full flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
        </div>
      ) : !filteredAppList || filteredAppList.length === 0 ? (
        <div className="col-span-full text-center text-theme-primary text-xl">
          {searchTerm ? 'No applications found matching your search.' : 'No applications have been created yet.'}
        </div>
      ) : (
        filteredAppList.map((app) => (
          <div
            key={app.ID}
            onClick={() => onAppClick(app.AppName)}
            className={"bg-theme-card backdrop-blur-lg rounded-lg p-6 text-theme-primary hover:bg-theme-card-hover transition-colors cursor-pointer sharedCard"}
            style={{ ['--card-color' as any]: '#8B5CF6' }}
          >
            <div className="flex items-center mb-4 min-w-0 w-full">
              <div className="relative w-12 h-12 flex-shrink-0">
                <div className="sharedCardIcon w-12 h-12">
                  <AppLogo name={app.AppName} logo={app.Logo} />
                </div>
                {app.Private && (
                  <div className="absolute -bottom-1 -right-1 bg-red-500 rounded-full p-1 z-10">
                    <svg 
                      className="w-3 h-3 text-theme-primary" 
                      fill="none" 
                      stroke="currentColor" 
                      viewBox="0 0 24 24"
                    >
                      <path 
                        strokeLinecap="round" 
                        strokeLinejoin="round" 
                        strokeWidth="2" 
                        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                      />
                    </svg>
                  </div>
                )}
              </div>
              <div className="ml-4 flex-1 min-w-0">
                <h3 
                  className="text-xl font-semibold truncate max-w-[200px] overflow-hidden sharedCardTitle" 
                  title={app.AppName}
                >
                  {app.AppName}
                </h3>
                {(app.Tuf || app.Reports || app.CdnEdge) && (
                  <div className="mt-1 flex items-center gap-1 flex-wrap">
                    {app.Tuf && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-300 border border-blue-400/30">
                        <svg 
                          className="w-3 h-3" 
                          fill="none" 
                          stroke="currentColor" 
                          viewBox="0 0 24 24"
                        >
                          <path 
                            strokeLinecap="round" 
                            strokeLinejoin="round" 
                            strokeWidth="2" 
                            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                          />
                        </svg>
                        TUF
                      </span>
                    )}
                    {app.Reports && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-300 border border-blue-400/30">
                        <svg
                          className="w-3 h-3"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M9 17v-6m3 6V7m3 10v-4m3 8H6a2 2 0 01-2-2V5a2 2 0 012-2h8l6 6v10a2 2 0 01-2 2z"
                          />
                        </svg>
                        Reports
                      </span>
                    )}
                    {app.CdnEdge && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-300 border border-blue-400/30">
                        <svg
                          className="w-3 h-3"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M3 15a4 4 0 014-4 5 5 0 019.9-1A3.5 3.5 0 1120 16H7a4 4 0 01-4-1z"
                          />
                        </svg>
                        CDN
                      </span>
                    )}
                  </div>
                )}
              </div>
              <div className="flex gap-2 flex-shrink-0 ml-auto">
                <button
                  onClick={(e) => handleEditApp(e, app)}
                  className="p-2 text-theme-primary hover:text-theme-primary-hover transition-colors duration-200"
                  title="Edit app"
                >
                  <i className="fas fa-edit"></i>
                </button>
                <button
                  onClick={(e) => handleDeleteApp(e, app)}
                  className="p-2 text-theme-danger hover:text-theme-primary-hover transition-colors duration-200"
                  title="Delete app"
                >
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </div>
            <div className="relative sharedCardContent">
              <div className="flex items-center gap-2">
                <p className={`text-sm text-white/70 flex-1 ${!expandedApps[app.ID] && 'line-clamp-1'} sharedCardDescription`}>
                  {app.Description || 'No description available'}
                </p>
                {app.Description && app.Description.length > 50 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setExpandedApps(prev => ({
                        ...prev,
                        [app.ID]: !prev[app.ID]
                      }));
                    }}
                    className="w-6 h-6 flex-shrink-0 flex items-center justify-center rounded-full bg-theme-card hover:bg-theme-card-hover transition-colors"
                    title={expandedApps[app.ID] ? 'Collapse' : 'Expand'}
                  >
                    <i className={`fas ${expandedApps[app.ID] ? 'fa-chevron-up' : 'fa-chevron-down'} text-theme-primary text-xs`}></i>
                  </button>
                )}
              </div>
            </div>
          </div>
        ))
      )}

      {showEditAppModal && selectedAppData && (
        <EditAppModal
          onClose={() => {
            setShowEditAppModal(false);
            setSelectedAppData(null);
          }}
          onSuccess={handleEditAppSave}
          appData={{
            id: selectedAppData.ID,
            app: selectedAppData.AppName,
            description: selectedAppData.Description,
            logo: selectedAppData.Logo,
            tuf: selectedAppData.Tuf,
            reports: selectedAppData.Reports,
            cdn: selectedAppData.CdnEdge,
            private: selectedAppData.Private,
            downloadMode: selectedAppData.DownloadMode
          }}
        />
      )}

      {showDeleteAppModal && selectedAppData && (
        <DeleteAppConfirmationModal
          appName={selectedAppData.AppName}
          onClose={() => {
            setShowDeleteAppModal(false);
            setSelectedAppData(null);
          }}
          onConfirm={handleDeleteAppConfirm}
        />
      )}
    </div>
  );
}; 