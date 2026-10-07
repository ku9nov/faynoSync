import { useQueries } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';
import { AppVersion, PaginatedResponse } from './useAppsQuery';

export type RolloutVersion = {
  appName: string;
  version: string;
  channel: string;
  configuredPercent: number;
};

type RolloutScope = {
  channels: string[];
  platforms: string[];
  architectures: string[];
};

type AdoptionFilters = RolloutScope & {
  range?: 'today' | 'week' | 'month';
  date?: string;
};

export type AppAdoption = {
  usage: Array<{ version: string; client_count: number }>;
  uniqueClients: number;
};

export const useRolloutVersions = (appNames: string[], scope: RolloutScope) => {
  const results = useQueries({
    queries: appNames.map((appName) => ({
      queryKey: ['rollout-search', appName, scope],
      queryFn: async (): Promise<AppVersion[]> => {
        const params = new URLSearchParams({ app_name: appName, limit: '100', page: '1' });
        if (scope.channels.length === 1) params.append('channel', scope.channels[0]);
        if (scope.platforms.length === 1) params.append('platform', scope.platforms[0]);
        if (scope.architectures.length === 1) params.append('arch', scope.architectures[0]);
        const response = await axiosInstance.get(`/search?${params.toString()}`);
        const data = response.data as PaginatedResponse<AppVersion> | AppVersion[];
        return Array.isArray(data) ? data : data.items ?? [];
      },
    })),
  });

  const isLoading = results.some((r) => r.isLoading);

  const rolloutVersions: RolloutVersion[] = [];
  const seen = new Set<string>();
  results.forEach((r, index) => {
    (r.data ?? []).forEach((v) => {
      if (v.RolloutPercent == null || v.RolloutPercent >= 100) {
        return;
      }
      const key = `${appNames[index]}|${v.Channel}|${v.Version}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      rolloutVersions.push({
        appName: appNames[index],
        version: v.Version,
        channel: v.Channel,
        configuredPercent: v.RolloutPercent,
      });
    });
  });

  return { rolloutVersions, isLoading };
};

export const useRolloutAdoption = (appNames: string[], filters: AdoptionFilters) => {
  const results = useQueries({
    queries: appNames.map((appName) => ({
      queryKey: ['rollout-adoption', appName, filters],
      queryFn: async (): Promise<AppAdoption> => {
        const params = new URLSearchParams();
        params.append('apps', appName);
        if (filters.channels.length) params.append('channels', filters.channels.join(','));
        if (filters.platforms.length) params.append('platforms', filters.platforms.join(','));
        if (filters.architectures.length) params.append('architectures', filters.architectures.join(','));
        if (filters.range) {
          if (filters.range === 'today') {
            params.append('date', new Date().toISOString().split('T')[0]);
          } else {
            params.append('range', filters.range);
          }
        }
        if (filters.date) {
          params.append('date', filters.date);
        }
        const response = await axiosInstance.get(`/telemetry?${params.toString()}`);
        return {
          usage: response.data.versions?.usage ?? [],
          uniqueClients: response.data.summary?.unique_clients ?? 0,
        };
      },
    })),
  });

  const byApp: Record<string, AppAdoption> = {};
  results.forEach((r, index) => {
    if (r.data) {
      byApp[appNames[index]] = r.data;
    }
  });

  return { byApp, isLoading: results.some((r) => r.isLoading) };
};
