import { useQuery } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';

interface Permission {
  Create: boolean;
  Delete: boolean;
  Edit: boolean;
  Download?: boolean;
  Upload?: boolean;
  Allowed: string[];
}

interface Permissions {
  Apps?: Permission;
  Channels?: Permission;
  Platforms?: Permission;
  Archs?: Permission;
}

interface UserData {
  id: string;
  username: string;
  is_admin: boolean;
  owner?: string;
  permissions?: Permissions;
}

export const useUsersQuery = () => {
  return useQuery<UserData>({
    queryKey: ['user'],
    queryFn: async () => {
      const response = await axiosInstance.get('/whoami');
      return response.data;
    },
    gcTime: Infinity, // Keep the data in cache indefinitely
    staleTime: Infinity, // This ensures we don't refetch unless explicitly invalidated
  });
}; 