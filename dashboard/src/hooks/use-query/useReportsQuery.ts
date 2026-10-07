import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';
import { PaginatedResponse } from '@/hooks/use-query/useAppsQuery';

export type ReportStatus = 'open' | 'resolved' | 'muted';

export type ReportGroup = {
  id: string;
  group_hash: string;
  app_id: string;
  application: {
    name: string;
    version: string;
    channel: string;
  };
  system: {
    platform: string;
    arch: string;
  };
  event: {
    type: string;
    reason: string;
  };
  stats: {
    count: number;
    first_seen: string;
    last_seen: string;
    details_stored: number;
    details_rejected: number;
  };
  status: ReportStatus;
  tags?: string[] | null;
  note?: string | null;
  resolved_at?: string | null;
  resolved_by?: string | null;
  created_at: string;
  updated_at: string;
};

export type ReportBlob = {
  id: string;
  group_hash: string;
  app_id: string;
  application: {
    name: string;
    version: string;
    channel: string;
  };
  system: {
    platform: string;
    arch: string;
  };
  event: {
    type: string;
    reason: string;
  };
  storage: {
    driver: string;
    key: string;
    compressed_size: number;
    decompressed_size: number;
    content_type: string;
    encoding: string;
  };
  created_at: string;
  expires_at: string;
  url: string;
};

export type ReportStatusFilter = ReportStatus | 'all';

export type ReportFilters = {
  status?: ReportStatusFilter;
  app?: string;
  version?: string;
  channel?: string;
  platform?: string;
  arch?: string;
  type?: string;
  reason?: string;
  from?: string;
  to?: string;
};

export const useReportsQuery = (page: number = 1, limit: number = 20, filters: ReportFilters = {}) => {
  const { data, isLoading, refetch } = useQuery<PaginatedResponse<ReportGroup>>({
    queryKey: ['reports', page, limit, filters],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
      });
      (Object.entries(filters) as [keyof ReportFilters, string | undefined][]).forEach(([key, value]) => {
        if (value) {
          params.append(key, value);
        }
      });
      const response = await axiosInstance.get(`/reports/groups?${params.toString()}`);
      return response.data;
    },
  });

  return { reports: data, isLoading, refetch };
};

export const useReportBlobsQuery = (groupHash: string | null) => {
  const { data, isLoading, refetch } = useQuery<{ items: ReportBlob[] }>({
    queryKey: ['report-blobs', groupHash],
    queryFn: async () => {
      const response = await axiosInstance.get(`/reports/groups/${groupHash}/blobs`);
      return response.data;
    },
    enabled: !!groupHash,
  });

  return { blobs: data?.items ?? [], isLoading, refetch };
};

export const useReportGroupMutations = () => {
  const queryClient = useQueryClient();

  const updateGroupMutation = useMutation({
    mutationFn: async ({
      groupHash,
      status,
      tags,
      note,
    }: {
      groupHash: string;
      status?: ReportStatus;
      tags?: string[];
      note?: string;
    }) => {
      const body: Record<string, unknown> = {};
      if (status !== undefined) body.status = status;
      if (tags !== undefined) body.tags = tags;
      if (note !== undefined) body.note = note;
      const response = await axiosInstance.patch(`/reports/groups/${groupHash}`, body);
      return response.data as { group_hash: string; status: ReportStatus };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
  });

  const deleteGroupMutation = useMutation({
    mutationFn: async (groupHash: string) => {
      const response = await axiosInstance.delete(`/reports/groups/${groupHash}`);
      return response.data as { group_hash: string; deleted: boolean };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
  });

  return { updateGroupMutation, deleteGroupMutation };
};
