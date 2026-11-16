import { type ReactElement } from 'react';
import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastContainer } from 'react-toastify';
import { ThemeProvider } from '@/providers/themeProvider';
import { AuthProvider } from '@/providers/authProvider';

const LocationProbe = () => {
  const location = useLocation();
  return <div data-testid="location" hidden>{location.pathname + location.search}</div>;
};

const clients: QueryClient[] = [];

// Components schedule refetches seconds after an action; an emptied cache turns those into no-ops
// instead of requests that land in the next test.
export const clearQueryClients = () => {
  clients.splice(0).forEach((client) => client.clear());
};

type Options = {
  route?: string;
  path?: string;
  token?: string | null;
  state?: unknown;
};

export const renderWithProviders = (ui: ReactElement, { route = '/', path = '/', token = 'test-token', state }: Options = {}) => {
  if (token) localStorage.setItem('token', token);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
  clients.push(queryClient);
  const user = userEvent.setup();
  const result = render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <MemoryRouter initialEntries={[{ pathname: route.split('?')[0], search: route.includes('?') ? `?${route.split('?')[1]}` : '', state }]}>
          <AuthProvider>
            <ToastContainer />
            <Routes>
              <Route path={path} element={ui} />
              <Route path="*" element={<div>other route</div>} />
            </Routes>
            <LocationProbe />
          </AuthProvider>
        </MemoryRouter>
      </ThemeProvider>
    </QueryClientProvider>,
  );
  return { ...result, user, queryClient };
};
