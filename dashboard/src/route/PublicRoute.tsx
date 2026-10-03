import { PropsWithChildren, FC } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/providers/authProvider.tsx';

export const PublicRoute: FC<PropsWithChildren> = ({ children }) => {
  const { token } = useAuth();
  const location = useLocation();

  if (token) {
    const from = location.state?.from || '/';
    return <Navigate to={from} replace />;
  }

  return children;
};
