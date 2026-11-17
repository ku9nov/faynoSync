import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RouterProvider } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@/providers/themeProvider';
import { router } from '@/route/router';
import { useFakeApi } from '../fakeApi';

// Data routers build a Request with jsdom's AbortSignal, which Node's Request rejects; navigation
// here never needs aborting, so the signal is dropped.
const NativeRequest = globalThis.Request;
beforeAll(() => {
  globalThis.Request = class extends NativeRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(input, init && { ...init, signal: undefined });
    }
  } as typeof Request;
});
afterAll(() => {
  globalThis.Request = NativeRequest;
});

beforeEach(() => {
  useFakeApi();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

// The router is a module singleton: navigate before rendering so the previous test's location never
// renders (a private page without a token would redirect to /signin mid-test).
const renderApp = async (path: string) => {
  await router.navigate(path);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    </QueryClientProvider>,
  );
};

describe('router', () => {
  it.each([
    ['/', 'Applications'],
    ['/applications', 'Applications'],
    ['/channels', 'Channels'],
    ['/platforms', 'Platforms'],
    ['/architectures', 'Architectures'],
    ['/statistics', 'Statistics'],
    ['/reports', 'Reports'],
    ['/settings', 'Settings'],
    ['/settings/tuf', 'Settings'],
    ['/settings/tokens', 'Settings'],
  ])('serves %s behind the login', async (path, heading) => {
    localStorage.setItem('token', 'test-token');
    await renderApp(path);
    expect((await screen.findAllByRole('heading', { name: heading })).length).toBeGreaterThan(0);
    expect(window.location.pathname).toBe(`/dashboard${path}`);
  });

  it('opens an application by name', async () => {
    localStorage.setItem('token', 'test-token');
    await renderApp('/applications/alpha');
    expect((await screen.findAllByTitle('alpha')).length).toBeGreaterThan(0);
  });

  it.each(['/channels', '/settings/tuf'])('sends %s to sign-in without a token', async (path) => {
    await renderApp(path);
    expect(await screen.findByRole('button', { name: 'Login' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/dashboard/signin');
  });

  it('serves the sign-up page without a token', async () => {
    await renderApp('/signup');
    expect(await screen.findByRole('button', { name: 'Register' })).toBeInTheDocument();
  });

  it('keeps a signed-in user away from sign-in', async () => {
    localStorage.setItem('token', 'test-token');
    await renderApp('/signin');
    expect((await screen.findAllByRole('heading', { name: 'Applications' })).length).toBeGreaterThan(0);
  });

  it('renders the error page for an unknown route', async () => {
    await renderApp('/nope');
    expect(await screen.findByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByText('404 Not Found')).toBeInTheDocument();
  });
});
