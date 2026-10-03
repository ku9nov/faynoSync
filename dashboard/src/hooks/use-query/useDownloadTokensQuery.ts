import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

export type DownloadToken = {
  id: string;
  app_id: string;
  app_name: string;
  channel_id: string;
  channel_name: string;
  token_prefix: string;
  updated_at: string;
};

export type RegeneratedDownloadToken = {
  app_id: string;
  channel_id: string;
  token: string;
};

export const useDownloadTokensQuery = (enabled: boolean) => {
  const queryClient = useQueryClient();

  const { data: downloadTokens = [], isLoading, isError } = useQuery<DownloadToken[]>({
    queryKey: ['downloadTokens'],
    queryFn: async () => {
      const response = await axiosInstance.get('/download-tokens/list');
      return response.data.download_tokens || [];
    },
    enabled,
  });

  const regenerateMutation = useMutation({
    mutationFn: async ({ appId, channelId }: { appId: string; channelId?: string }) => {
      const response = await axiosInstance.post('/download-tokens/regenerate', {
        app_id: appId,
        ...(channelId && { channel_id: channelId }),
      });
      return response.data as RegeneratedDownloadToken;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['downloadTokens'] });
    },
  });

  const regenerateDownloadToken = (appId: string, channelId?: string) =>
    regenerateMutation.mutateAsync({ appId, channelId });

  return { downloadTokens, isLoading, isError, regenerateDownloadToken };
};
