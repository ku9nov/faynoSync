import { useMutation } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

interface AdminUpdateData {
  id: string;
  username: string;
  password: string;
}

export const useAdminUpdateQuery = () => {
  const updateAdminMutation = useMutation({
    mutationFn: async (data: AdminUpdateData) => {
      const response = await axiosInstance.post('/admin/update', data);
      return response.data;
    },
  });

  const updateAdmin = async (data: AdminUpdateData) => {
    return await updateAdminMutation.mutateAsync(data);
  };

  return { 
    updateAdmin, 
    isLoading: updateAdminMutation.isPending, 
    error: updateAdminMutation.error 
  };
}; 