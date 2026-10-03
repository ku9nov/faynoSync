import { PropsWithChildren, FC } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/providers/authProvider.tsx';

export const PrivateRoute: FC<PropsWithChildren> = ({ children }) => {
  const { token } = useAuth();
  const location = useLocation();

  if (!token) {
    return <Navigate to="/signin" state={{ from: location.pathname + location.search }} replace />;
  }

  return children;
};
