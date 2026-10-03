import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

export type Architecture = {
  ID: string;
  ArchID: string;
  Updated_at: string;
};

export const useArchitectureQuery = () => {
  const queryClient = useQueryClient();

  const { data: architectures = [], isLoading, refetch } = useQuery<Architecture[]>({
    queryKey: ['architectures'],
    queryFn: async () => {
      const response = await axiosInstance.get('/arch/list');
      return response.data.archs || [];
    },
  });

  const createArchitectureMutation = useMutation({
    mutationFn: async (archName: string) => {
      const response = await axiosInstance.post('/arch/create', { arch: archName }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['architectures'] });
    },
  });

  const createArchitecture = async (archName: string) => {
    await createArchitectureMutation.mutateAsync(archName);
  };

  const deleteArchitectureMutation = useMutation({
    mutationFn: async (archId: string) => {
      await axiosInstance.delete(`/arch/delete?id=${archId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['architectures'] });
    },
  });

  const deleteArchitecture = async (archId: string) => {
    await deleteArchitectureMutation.mutateAsync(archId);
  };

  const updateArchitectureMutation = useMutation({
    mutationFn: async ({ id, newName }: { id: string; newName: string }) => {
      const response = await axiosInstance.post('/arch/update', { id, arch: newName }, {
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['architectures'] });
    },
  });

  const updateArchitecture = async (id: string, newName: string) => {
    await updateArchitectureMutation.mutateAsync({ id, newName });
  };

  return { architectures, deleteArchitecture, createArchitecture, updateArchitecture, isLoading, refetch };
};
