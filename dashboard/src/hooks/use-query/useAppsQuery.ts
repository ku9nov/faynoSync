import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

export type Artifact = {
  ID: string;
  link: string;
  platform: string;
  arch: string;
  package: string;
  TufTaskID?: string | null;
  TufSigned?: boolean;
  IsFeed?: boolean;
};

export type ChangelogEntry = {
  Version: string;
  Changes: string;
  Date: string;
};

export type AppVersion = {
  ID: string;
  AppName: string;
  Version: string;
  Channel: string;
  Published: boolean;
  Critical: boolean;
  Intermediate: boolean;
  RolloutPercent?: number | null;
  Artifacts: Artifact[];
  Changelog: ChangelogEntry[];
  Updated_at: string;
};

export type DownloadMode = 'unlisted' | 'strict';

export type AppListItem = {
  ID: string;
  AppName: string;
  Logo: string;
  Description: string;
  Updated_at: string;
  isExpanded?: boolean;
  Private?: boolean;
  DownloadMode?: DownloadMode;
  Tuf?: boolean;
  Reports?: boolean;
  CdnEdge?: boolean;
};

export type PaginatedResponse<T> = {
  items: T[];
  total: number;
  page: number;
  limit: number;
};

export interface VersionFilters {
  channel: string;
  published: boolean | null;
  critical: boolean | null;
  platform: string;
  arch: string;
}

export type BulkDeleteOutcome = {
  deletedIds: string[];
  orphanedLinks: string[];
  remainingIds: string[];
  error: string | null;
};

// Mirrors MAX_BULK_DELETE_VERSIONS on the server. A page holds 9 versions, so a
// page-wide selection still goes out as one all-or-nothing request.
const BULK_DELETE_CHUNK = 10;

const buildSearchParams = (
  appName: string,
  page: number,
  limit: number,
  filters?: VersionFilters,
) => {
  const params = new URLSearchParams({
    app_name: appName,
    limit: limit.toString(),
    page: page.toString(),
  });

  if (filters) {
    if (filters.channel) params.append('channel', filters.channel);
    if (filters.published !== null) params.append('published', filters.published.toString());
    if (filters.critical !== null) params.append('critical', filters.critical.toString());
    if (filters.platform) params.append('platform', filters.platform);
    if (filters.arch) params.append('arch', filters.arch);
  }

  return params;
};

const requestVersionDelete = async (ids: string[]) => {
  const params = new URLSearchParams();
  ids.forEach(id => params.append('id', id));
  const response = await axiosInstance.delete(`/apps/delete?${params.toString()}`);
  return response.data;
};

const describeDeleteError = (err: unknown): string => {
  const data = (err as { response?: { data?: Record<string, unknown> } })?.response?.data;
  if (!data) {
    return (err as Error)?.message || 'Failed to delete versions';
  }

  const parts = [String(data.error || 'Failed to delete versions')];
  if (data.details) parts.push(String(data.details));
  for (const key of ['forbidden', 'not_found', 'apps'] as const) {
    const list = data[key];
    if (Array.isArray(list) && list.length > 0) {
      parts.push(`${key.replace('_', ' ')}: ${list.join(', ')}`);
    }
  }
  return parts.join(' - ');
};

export const useAppsQuery = (
  appName?: string, 
  page: number = 1, 
  refreshKey: number = 0,
  filters?: VersionFilters
) => {
  const queryClient = useQueryClient();

  const { data: apps = [], isLoading, refetch } = useQuery<AppVersion[] | AppListItem[] | PaginatedResponse<AppVersion>>({
    queryKey: ['apps', appName, page, refreshKey, filters],
    queryFn: async () => {
      if (appName) {
        const params = buildSearchParams(appName, page, 9, filters);
        const response = await axiosInstance.get(`/search?${params.toString()}`);
        return response.data;
      } else {
        const response = await axiosInstance.get('/app/list');
        return response.data.apps || [];
      }
    },
  });

  const updateAppMutation = useMutation({
    mutationFn: async ({ 
      id, 
      data 
    }: { 
      id: string; 
      data: { 
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
        updater?: string;
        signature?: string;
        rollout?: number;
      }
    }) => {
      const formData = new FormData();
      const dataObj = {
        id,
        app_name: data.app_name,
        version: data.version,
        channel: data.channel,
        publish: data.Published,
        critical: data.Critical,
        intermediate: data.Intermediate,
        platform: data.Platform,
        arch: data.Arch,
        changelog: data.Changelog,
        ...(data.updater && { updater: data.updater }),
        ...(data.signature && { signature: data.signature }),
        ...(data.rollout !== undefined && { rollout: data.rollout }),
      };

      formData.append('data', JSON.stringify(dataObj));

      if (data.Files && data.Files.length > 0) {
        data.Files.forEach((file) => {
          formData.append('file', file);
        });
      }
  
      await axiosInstance.post(`/apps/update`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    },
  });

  const deleteAppMutation = useMutation({
    mutationFn: async (ids: string | string[]) =>
      requestVersionDelete(Array.isArray(ids) ? ids : [ids]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    },
  });

  const deleteArtifactMutation = useMutation({
    mutationFn: async ({ 
      id, 
      appName, 
      version, 
      artifactIndex 
    }: { 
      id: string; 
      appName: string; 
      version: string; 
      artifactIndex: number;
    }) => {
      const formData = new FormData();
      const data = {
        id,
        app_name: appName,
        version,
        artifacts_to_delete: [artifactIndex.toString()]
      };
      formData.append('data', JSON.stringify(data));

      await axiosInstance.post('/artifact/delete', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
    },
    onSuccess: async () => {
      // Invalidate and refetch to ensure we have the latest data
      await queryClient.invalidateQueries({ queryKey: ['apps'] });
      await queryClient.refetchQueries({ queryKey: ['apps'] });
    },
  });

  const updateApp = async (id: string, data: {
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
    updater?: string;
    signature?: string;
    rollout?: number;
  }) => {
    await updateAppMutation.mutateAsync({ id, data });
  };

  const deleteApp = async (id: string) => {
    await deleteAppMutation.mutateAsync(id);
  };

  // The server refuses more ids than MAX_BULK_DELETE_VERSIONS, so a selection wider
  // than one page goes out in chunks. Each chunk is atomic on its own; the run stops
  // at the first failing chunk so the report can name what is still there.
  const deleteVersions = async (
    ids: string[],
    onProgress?: (done: number, total: number) => void,
  ): Promise<BulkDeleteOutcome> => {
    const deletedIds: string[] = [];
    const orphanedLinks: string[] = [];
    let chunkSize = BULK_DELETE_CHUNK;
    let index = 0;

    while (index < ids.length) {
      const chunk = ids.slice(index, index + chunkSize);
      try {
        const data = await requestVersionDelete(chunk);
        if (Array.isArray(data?.orphaned_links)) {
          orphanedLinks.push(...data.orphaned_links);
        }
        deletedIds.push(...chunk);
        index += chunk.length;
        onProgress?.(deletedIds.length, ids.length);
      } catch (err) {
        const data = (err as { response?: { data?: { limit?: number } } })?.response?.data;
        const serverLimit = typeof data?.limit === 'number' ? data.limit : 0;
        if (serverLimit > 0 && serverLimit < chunkSize) {
          chunkSize = serverLimit;
          continue;
        }
        return {
          deletedIds,
          orphanedLinks,
          remainingIds: ids.slice(index),
          error: describeDeleteError(err),
        };
      }
    }

    return { deletedIds, orphanedLinks, remainingIds: [], error: null };
  };

  const fetchAllMatchingVersions = async (total: number): Promise<AppVersion[]> => {
    if (!appName || total <= 0) return [];
    const params = buildSearchParams(appName, 1, total, filters);
    const response = await axiosInstance.get(`/search?${params.toString()}`);
    return (response.data?.items || []) as AppVersion[];
  };

  const deleteArtifact = async (id: string, appName: string, version: string, artifactIndex: number) => {
    await deleteArtifactMutation.mutateAsync({ id, appName, version, artifactIndex });
  };

  const getVersionById = (id: string): AppVersion | undefined => {
    
    if (Array.isArray(apps)) {
      const found = apps.find(app => app.ID === id) as AppVersion;
      return found;
    }
    if ('items' in apps) {
      const found = apps.items.find(app => app.ID === id) as AppVersion;
      return found;
    }
    return undefined;
  };

  return { apps, updateApp, deleteApp, deleteVersions, fetchAllMatchingVersions, getVersionById, deleteArtifact, isLoading, refetch };
}; 