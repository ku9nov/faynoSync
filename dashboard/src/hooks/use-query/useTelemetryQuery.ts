import { useQuery } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';
import { useMemo } from 'react';

export type TelemetryData = {
  date: string;
  date_range?: string[];
  admin: string;
  summary: {
    total_requests: number;
    unique_clients: number;
    clients_using_latest_version: number;
    clients_outdated: number;
    total_active_apps: number;
  };
  daily_stats?: Array<{
    date: string;
    total_requests: number;
    unique_clients: number;
    clients_using_latest_version: number;
    clients_outdated: number;
  }>;
  versions: {
    used_versions_count: number;
    known_versions: string[];
    usage: Array<{
      version: string;
      client_count: number;
    }>;
  };
  platforms: Array<{
    platform: string;
    client_count: number;
  }>;
  architectures: Array<{
    arch: string;
    client_count: number;
  }>;
  channels: Array<{
    channel: string;
    client_count: number;
  }>;
};

type TelemetryFilters = {
  apps?: string[];
  channels?: string[];
  platforms?: string[];
  architectures?: string[];
  range?: 'today' | 'week' | 'month';
  date?: string;
};

export const useTelemetryQuery = (filters: TelemetryFilters = {}) => {
  const queryString = useMemo(() => {
    const params = new URLSearchParams();
    
    if (filters.apps?.length) {
      params.append('apps', filters.apps.join(','));
    }
    if (filters.channels?.length) {
      params.append('channels', filters.channels.join(','));
    }
    if (filters.platforms?.length) {
      params.append('platforms', filters.platforms.join(','));
    }
    if (filters.architectures?.length) {
      params.append('architectures', filters.architectures.join(','));
    }
    if (filters.range) {
      if (filters.range === 'today') {
        const today = new Date().toISOString().split('T')[0];
        params.append('date', today);
      } else {
        params.append('range', filters.range);
      }
    }
    if (filters.date) {
      params.append('date', filters.date);
    }

    return params.toString();
  }, [filters]);

  return useQuery<TelemetryData>({
    queryKey: ['telemetry', queryString],
    queryFn: async () => {
      const response = await axiosInstance.get(`/telemetry${queryString ? `?${queryString}` : ''}`);
      return response.data;
    },
  });
}; 