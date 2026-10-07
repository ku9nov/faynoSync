import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

export type Updater = {
  type: string;
  default?: boolean;
};

export type Platform = {
  ID: string;
  PlatformName: string;
  Updated_at: string;
  Updaters?: Updater[];
};

export const usePlatformQuery = () => {
  const queryClient = useQueryClient();

  const { data: platforms = [], isLoading, refetch } = useQuery<Platform[]>({
    queryKey: ['platforms'],
    queryFn: async () => {
      const response = await axiosInstance.get('/platform/list');
      return response.data.platforms || [];
    },
  });

  const createPlatformMutation = useMutation({
    mutationFn: async ({ platformName, updaters }: { platformName: string; updaters: Updater[] }) => {
      const response = await axiosInstance.post('/platform/create', { 
        platform: platformName,
        updaters 
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['platforms'] });
    },
  });

  const createPlatform = async (platformName: string, updaters: Updater[] = []) => {
    await createPlatformMutation.mutateAsync({ platformName, updaters });
  };

  const deletePlatformMutation = useMutation({
    mutationFn: async (platformId: string) => {
      await axiosInstance.delete(`/platform/delete?id=${platformId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['platforms'] });
    },
  });

  const deletePlatform = async (platformId: string) => {
    await deletePlatformMutation.mutateAsync(platformId);
  };

  const updatePlatformMutation = useMutation({
    mutationFn: async ({ id, newName, updaters }: { id: string; newName: string; updaters: Updater[] }) => {
      const response = await axiosInstance.post('/platform/update', { 
        id, 
        platform: newName,
        updaters 
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['platforms'] });
    },
  });

  const updatePlatform = async (id: string, newName: string, updaters: Updater[] = []) => {
    await updatePlatformMutation.mutateAsync({ id, newName, updaters });
  };

  return { platforms, deletePlatform, createPlatform, updatePlatform, isLoading, refetch };
}; 