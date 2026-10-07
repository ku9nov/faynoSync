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

interface User {
  id: string;
  username: string;
  permissions: Permissions;
  updated_at: string;
}

interface UsersResponse {
  users: User[];
}

export const useUsersListQuery = () => {
  return useQuery<UsersResponse>({
    queryKey: ['users-list'],
    queryFn: async () => {
      const response = await axiosInstance.get('/users/list');
      return response.data;
    },
  });
}; 