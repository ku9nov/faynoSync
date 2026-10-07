import { useMutation, useQueryClient } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

export type UploadData = {
  app_name: string;
  version: string;
  channel: string;
  publish: boolean;
  critical: boolean;
  intermediate: boolean;
  platform: string;
  arch: string;
  changelog?: string;
  files: File[];
  updater?: string;
  signature?: string;
};

export const useUploadQuery = () => {
  const queryClient = useQueryClient();

  const uploadMutation = useMutation({
    mutationFn: async (data: UploadData) => {
      const formData = new FormData();
      
      data.files.forEach(file => {
        formData.append('file', file);
      });

      const jsonData = {
        app_name: data.app_name,
        version: data.version,
        channel: data.channel,
        publish: data.publish,
        critical: data.critical,
        intermediate: data.intermediate,
        platform: data.platform,
        arch: data.arch,
        changelog: data.changelog,
        ...(data.updater && { updater: data.updater }),
        ...(data.signature && { signature: data.signature }),
      };

      formData.append('data', JSON.stringify(jsonData));

      const response = await axiosInstance.post('/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    },
  });

  const upload = async (data: UploadData) => {
    return await uploadMutation.mutateAsync(data);
  };

  return { upload, isLoading: uploadMutation.isPending, error: uploadMutation.error };
}; 