import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { render } from '@testing-library/react';
import { API, server } from '../msw';
import { renderWithProviders } from '../render';
import { SignInPage } from '@/pages/SignInPage';
import { SignUpPage } from '@/pages/SignUpPage';
import { PrivateRoute } from '@/route/PrivateRoute';
import { PublicRoute } from '@/route/PublicRoute';
import { RouteError } from '@/components/RouteError';
import axiosInstance from '@/config/axios';

const location = () => screen.getByTestId('location').textContent;

describe('SignInPage', () => {
  it('validates before calling the API', async () => {
    const { user } = renderWithProviders(<SignInPage />, { route: '/signin', path: '/signin', token: null });
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(await screen.findAllByText('Required field')).toHaveLength(2);
    await user.type(screen.getByPlaceholderText('Username'), 'ab');
    await user.type(screen.getByPlaceholderText('password'), '123');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(await screen.findByText('Minimum 3 symbol')).toBeInTheDocument();
    expect(screen.getByText('Minimum 6 symbol')).toBeInTheDocument();
  });

  it('logs in, stores the token and goes to applications', async () => {
    let body: unknown;
    server.use(
      http.post(`${API}/login`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ token: 'jwt-1' });
      }),
    );
    const { user } = renderWithProviders(<SignInPage />, { route: '/signin', path: '/signin', token: null });
    await user.type(screen.getByPlaceholderText('Username'), 'admin');
    await user.type(screen.getByPlaceholderText('password'), 'secret123');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    await waitFor(() => expect(location()).toBe('/applications'));
    expect(body).toEqual({ username: 'admin', password: 'secret123' });
    expect(localStorage.getItem('token')).toBe('jwt-1');
  });

  it('returns to the page the user came from', async () => {
    server.use(http.post(`${API}/login`, () => HttpResponse.json({ token: 'jwt-1' })));
    const { user } = renderWithProviders(<SignInPage />, {
      route: '/signin',
      path: '/signin',
      token: null,
      state: { from: '/reports?app=x' },
    });
    await user.type(screen.getByPlaceholderText('Username'), 'admin');
    await user.type(screen.getByPlaceholderText('password'), 'secret123');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    await waitFor(() => expect(location()).toBe('/reports?app=x'));
  });

  it('shows the server error', async () => {
    server.use(http.post(`${API}/login`, () => HttpResponse.json({ error: 'invalid credentials' }, { status: 401 })));
    const { user } = renderWithProviders(<SignInPage />, { route: '/signin', path: '/signin', token: null });
    await user.type(screen.getByPlaceholderText('Username'), 'admin');
    await user.type(screen.getByPlaceholderText('password'), 'wrong12');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(await screen.findByText('invalid credentials')).toBeInTheDocument();
    expect(localStorage.getItem('token')).toBeNull();
    expect(location()).toBe('/signin');
  });

  it('links to registration', async () => {
    const { user } = renderWithProviders(<SignInPage />, { route: '/signin', path: '/signin', token: null });
    await user.click(screen.getByRole('button', { name: 'Register' }));
    expect(location()).toBe('/signup');
  });
});

describe('SignUpPage', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  const fill = async (user: ReturnType<typeof renderWithProviders>['user'], confirm = 'secret123') => {
    await user.type(screen.getByPlaceholderText('Username'), 'newuser');
    await user.type(screen.getByPlaceholderText('password'), 'secret123');
    await user.type(screen.getByPlaceholderText('Confirm Password'), confirm);
    await user.type(screen.getByPlaceholderText('secretKey'), 'sk');
  };

  it('requires matching passwords', async () => {
    const { user } = renderWithProviders(<SignUpPage />, { route: '/signup', path: '/signup', token: null });
    await fill(user, 'different');
    await user.click(screen.getByRole('button', { name: 'Register' }));
    expect(await screen.findByText('Passwords must match')).toBeInTheDocument();
  });

  it('sends the secret key as api_key and goes to applications', async () => {
    let body: unknown;
    server.use(
      http.post(`${API}/signup`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ result: 'ok' });
      }),
    );
    const { user } = renderWithProviders(<SignUpPage />, { route: '/signup', path: '/signup', token: null });
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Register' }));
    await waitFor(() => expect(location()).toBe('/applications'));
    expect(body).toEqual({ username: 'newuser', password: 'secret123', api_key: 'sk' });
    expect(await screen.findByText('Signed Up successfully.')).toBeInTheDocument();
  });

  it('shows the server error', async () => {
    server.use(http.post(`${API}/signup`, () => HttpResponse.json({ error: 'wrong api key' }, { status: 400 })));
    const { user } = renderWithProviders(<SignUpPage />, { route: '/signup', path: '/signup', token: null });
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Register' }));
    expect(await screen.findByText('wrong api key')).toBeInTheDocument();
    expect(location()).toBe('/signup');
  });
});

describe('route guards', () => {
  it('PrivateRoute sends anonymous users to sign-in', () => {
    renderWithProviders(<PrivateRoute>secret page</PrivateRoute>, { route: '/reports?x=1', path: '/reports', token: null });
    expect(screen.queryByText('secret page')).toBeNull();
    expect(location()).toBe('/signin');
  });

  it('PrivateRoute renders for signed-in users', () => {
    renderWithProviders(<PrivateRoute>secret page</PrivateRoute>, { route: '/reports', path: '/reports' });
    expect(screen.getByText('secret page')).toBeInTheDocument();
  });

  it('PublicRoute sends signed-in users back where they came from', () => {
    renderWithProviders(<PublicRoute>login form</PublicRoute>, {
      route: '/signin',
      path: '/signin',
      state: { from: '/channels' },
    });
    expect(screen.queryByText('login form')).toBeNull();
    expect(location()).toBe('/channels');
  });

  it('PublicRoute renders for anonymous users', () => {
    renderWithProviders(<PublicRoute>login form</PublicRoute>, { route: '/signin', path: '/signin', token: null });
    expect(screen.getByText('login form')).toBeInTheDocument();
  });
});

describe('axios instance', () => {
  it('sends the bearer token', async () => {
    localStorage.setItem('token', 'abc');
    let auth: string | null = null;
    server.use(
      http.get(`${API}/ping`, ({ request }) => {
        auth = request.headers.get('authorization');
        return HttpResponse.json({});
      }),
    );
    await axiosInstance.get('/ping');
    expect(auth).toBe('Bearer abc');
  });

  it('drops the token on 401', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    localStorage.setItem('token', 'abc');
    server.use(http.get(`${API}/ping`, () => HttpResponse.json({}, { status: 401 })));
    await expect(axiosInstance.get('/ping')).rejects.toThrow();
    expect(localStorage.getItem('token')).toBeNull();
  });

  it('keeps the token on other errors', async () => {
    localStorage.setItem('token', 'abc');
    server.use(http.get(`${API}/ping`, () => HttpResponse.json({}, { status: 403 })));
    await expect(axiosInstance.get('/ping')).rejects.toThrow();
    expect(localStorage.getItem('token')).toBe('abc');
  });
});

describe('RouteError', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  const Thrower = ({ error }: { error: unknown }): never => {
    throw error;
  };

  const renderError = (error: unknown, entry = '/') => {
    const router = createMemoryRouter(
      [{ path: '/', element: <Thrower error={error} />, errorElement: <RouteError /> }],
      { initialEntries: [entry] },
    );
    render(<RouterProvider router={router} />);
  };

  it('shows the error message', async () => {
    renderError(new Error('kaboom'));
    expect(await screen.findByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByText('kaboom')).toBeInTheDocument();
  });

  it('shows status for route responses', async () => {
    renderError(null, '/missing');
    expect(await screen.findByText('404 Not Found')).toBeInTheDocument();
  });

  it('reloads once on a stale chunk, then asks the user', async () => {
    const message = 'Failed to fetch dynamically imported module: /dashboard/assets/x.js';
    renderError(new Error(message));
    await waitFor(() => expect(sessionStorage.getItem('staleChunkReloadFor')).toContain(message));
    expect(screen.queryByText('Dashboard updated')).toBeNull();
  });

  it('does not loop reloads for the same chunk', async () => {
    const message = 'Failed to fetch dynamically imported module: /dashboard/assets/x.js';
    renderError(new Error(message));
    await waitFor(() => expect(sessionStorage.getItem('staleChunkReloadFor')).not.toBeNull());
    renderError(new Error(message));
    expect(await screen.findByText('Dashboard updated')).toBeInTheDocument();
  });
});
