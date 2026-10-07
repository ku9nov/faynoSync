import { createBrowserRouter } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { PrivateRoute } from '@/route/PrivateRoute.tsx';
import { PublicRoute } from '@/route/PublicRoute.tsx';
import { AuthProvider } from '@/providers/authProvider.tsx';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { LoadingSpinner } from '@/components/LoadingSpinner';

// Lazy load page components
const SignInPage = lazy(() => import('@/pages/SignInPage.tsx').then(module => ({ default: module.SignInPage })));
const SignUpPage = lazy(() => import('@/pages/SignUpPage.tsx').then(module => ({ default: module.SignUpPage })));
const HomePage = lazy(() => import('@/pages/HomePage.tsx').then(module => ({ default: module.HomePage })));
const ChannelsPage = lazy(() => import('@/pages/ChannelsPage.tsx').then(module => ({ default: module.ChannelsPage })));
const PlatformsPage = lazy(() => import('@/pages/PlatformsPage.tsx').then(module => ({ default: module.PlatformsPage })));
const ArchitecturesPage = lazy(() => import('@/pages/ArchitecturesPage.tsx').then(module => ({ default: module.ArchitecturesPage })));
const StatisticsPage = lazy(() => import('@/pages/StatisticsPage.tsx').then(module => ({ default: module.StatisticsPage })));
const ReportsPage = lazy(() => import('@/pages/ReportsPage.tsx').then(module => ({ default: module.ReportsPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage.tsx').then(module => ({ default: module.SettingsPage })));

const RootLayout = ({ children }: { children: React.ReactNode }) => (
  <AuthProvider>
    <ToastContainer />
    <Suspense fallback={<LoadingSpinner />}>
    {children}
    </Suspense>
  </AuthProvider>
);

export const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout><PrivateRoute><HomePage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/applications',
    element: <RootLayout><PrivateRoute><HomePage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/applications/:appName',
    element: <RootLayout><PrivateRoute><HomePage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/channels',
    element: <RootLayout><PrivateRoute><ChannelsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/platforms',
    element: <RootLayout><PrivateRoute><PlatformsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/architectures',
    element: <RootLayout><PrivateRoute><ArchitecturesPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/statistics',
    element: <RootLayout><PrivateRoute><StatisticsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/reports',
    element: <RootLayout><PrivateRoute><ReportsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/settings',
    element: <RootLayout><PrivateRoute><SettingsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/settings/tuf',
    element: <RootLayout><PrivateRoute><SettingsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/settings/tokens',
    element: <RootLayout><PrivateRoute><SettingsPage /></PrivateRoute></RootLayout>,
  },
  {
    path: '/signin',
    element: <RootLayout><PublicRoute><SignInPage /></PublicRoute></RootLayout>,
  },
  {
    path: '/signup',
    element: <RootLayout><PublicRoute><SignUpPage /></PublicRoute></RootLayout>,
  },
], { basename: import.meta.env.BASE_URL });
