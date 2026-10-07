import { useQuery } from '@tanstack/react-query';
import axiosInstance from '@/config/axios';
import { AppListItem } from '@/hooks/use-query/useAppsQuery';

export const useAppDataQuery = (appName?: string | null) => {
  return useQuery({
    queryKey: ['appData', appName],
    queryFn: async () => {
      if (!appName) return null;
      const response = await axiosInstance.get('/app/list');
      const app = response.data.apps.find((a: AppListItem) => a.AppName === appName);
      return (app as AppListItem) || null;
    },
    enabled: !!appName,
  });
};
