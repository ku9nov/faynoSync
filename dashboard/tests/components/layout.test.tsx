import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { db, lastCall, route, useFakeApi } from '../fakeApi';
import { currentLocation } from '../helpers';
import { ChannelsPage } from '@/pages/ChannelsPage';
import { PrivateRoute } from '@/route/PrivateRoute';
import { Header } from '@/components/layout/Header';

beforeEach(() => useFakeApi());

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

const renderPage = () =>
  renderWithProviders(
    <PrivateRoute>
      <ChannelsPage />
    </PrivateRoute>,
    { route: '/channels', path: '/channels' },
  );

const openSettings = async (user: ReturnType<typeof renderPage>['user']) => {
  await screen.findByRole('heading', { name: 'stable' });
  await user.click(screen.getAllByRole('button', { name: 'Settings' })[0]);
};

describe('sidebar', () => {
  it.each([
    ['Applications', '/applications'],
    ['Platforms', '/platforms'],
    ['Architectures', '/architectures'],
    ['Statistics', '/statistics'],
    ['Reports', '/reports'],
  ])('navigates to %s', async (label, path) => {
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'stable' });
    await user.click(screen.getAllByRole('button', { name: label })[0]);
    expect(currentLocation()).toBe(path);
  });

  it('marks the current page', async () => {
    renderPage();
    await screen.findByRole('heading', { name: 'stable' });
    expect(screen.getAllByRole('button', { name: 'Channels' })[0]).toHaveAttribute('aria-current', 'page');
  });
});

describe('settings menu', () => {
  it('shows the user and the admin-only settings entry', async () => {
    const { user } = renderPage();
    await openSettings(user);
    expect(await screen.findByText('Administrator')).toBeInTheDocument();
    expect(screen.getByText('admin')).toBeInTheDocument();
    await user.click(screen.getByText('Settings', { selector: '.settings-popup-button span' }));
    expect(currentLocation()).toBe('/settings');
  });

  it('hides settings for team users', async () => {
    db.user = { id: 'u-2', username: 'dev', is_admin: false, owner: 'admin' };
    const { user } = renderPage();
    await openSettings(user);
    expect(await screen.findByText('Team user')).toBeInTheDocument();
    expect(document.querySelectorAll('.settings-popup-button')).toHaveLength(2);
  });

  it('switches and remembers the theme', async () => {
    const { user } = renderPage();
    await openSettings(user);
    const themes = within(screen.getByRole('group', { name: 'Theme' }));
    expect(themes.getByRole('button', { name: 'Auto' })).toHaveAttribute('aria-pressed', 'true');
    await user.click(themes.getByRole('button', { name: 'Light' }));
    expect(themes.getByRole('button', { name: 'Light' })).toHaveAttribute('aria-pressed', 'true');
    expect(themes.getByRole('button', { name: 'Auto' })).toHaveAttribute('aria-pressed', 'false');
    expect(localStorage.getItem('themeMode')).toBe('light');
  });

  it('logs out', async () => {
    const { user } = renderPage();
    await openSettings(user);
    await user.click(await screen.findByText('Logout'));
    expect(localStorage.getItem('token')).toBeNull();
    expect(currentLocation()).toBe('/signin');
  });
});

describe('profile', () => {
  const openProfile = async () => {
    const utils = renderPage();
    await openSettings(utils.user);
    await utils.user.click(await screen.findByText('Profile'));
    await screen.findByRole('heading', { name: /Change password/i });
    return utils;
  };

  const passwords = () => [...document.querySelectorAll('input[type="password"]')] as HTMLInputElement[];

  it('validates the new password', async () => {
    const { user } = await openProfile();
    const [password, confirm] = passwords();
    await user.type(password, 'short');
    await user.type(confirm, 'other');
    await user.click(screen.getByRole('button', { name: 'Change Password' }));
    expect(screen.getByText('New passwords do not match')).toBeInTheDocument();
    await user.clear(confirm);
    await user.type(confirm, 'short');
    await user.click(screen.getByRole('button', { name: 'Change Password' }));
    expect(screen.getByText('Password must be at least 8 characters long')).toBeInTheDocument();
  });

  it('generates and saves a password for the admin', async () => {
    server.use(route('post', '/admin/update', () => HttpResponse.json({ message: 'ok' })));
    const { user } = await openProfile();
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    const [password, confirm] = passwords();
    expect(password.value).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(confirm.value).toBe(password.value);
    const generated = password.value;
    await user.click(screen.getByRole('button', { name: 'Change Password' }));
    expect(await screen.findByText('Password changed successfully')).toBeInTheDocument();
    expect(lastCall('POST', '/admin/update').json).toEqual({ id: 'u-1', username: 'admin', password: generated });
  });

  it('copies the password, closes after saving and reports failures', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let fail = true;
    server.use(route('post', '/admin/update', () => (fail ? HttpResponse.json({ error: 'locked' }, { status: 423 }) : HttpResponse.json({}))));
    const { user } = await openProfile();
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy password' }));
    expect(writeText).toHaveBeenCalledWith(passwords()[0].value);
    expect(await screen.findByText('Password copied to clipboard!')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Change Password' }));
    expect(await screen.findByText(/locked|status code 423/)).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Change Password' }));
    expect(await screen.findByText('Password changed successfully')).toBeInTheDocument();
    expect(passwords()[0]).toHaveValue('');
    vi.advanceTimersByTime(1500);
    await waitFor(() => expect(screen.queryByRole('heading', { name: /Change password/i })).toBeNull());
  });

  it('lists every permission category of a team user', async () => {
    db.user = {
      id: 'u-3',
      username: 'qa',
      is_admin: false,
      owner: 'admin',
      permissions: {
        Apps: { Create: false, Delete: true, Edit: false, Upload: false, Download: true, Allowed: [] },
        Platforms: { Create: true, Delete: true, Edit: true, Allowed: ['pl-2'] },
        Archs: { Create: false, Delete: false, Edit: false, Allowed: ['ar-1'] },
      },
    };
    const { user } = renderPage();
    await openSettings(user);
    await user.click(await screen.findByText('Profile'));
    const table = within(await screen.findByRole('table'));
    expect(table.getByText('windows')).toBeInTheDocument();
    expect(table.getByText('amd64')).toBeInTheDocument();
    expect(table.getByText('None')).toBeInTheDocument();
  });

  it('shows team permissions with resolved names', async () => {
    db.user = {
      id: 'u-2',
      username: 'dev',
      is_admin: false,
      owner: 'admin',
      permissions: {
        Apps: { Create: true, Delete: false, Edit: true, Upload: true, Download: false, Allowed: ['app-1'] },
        Channels: { Create: false, Delete: false, Edit: false, Allowed: ['ch-2', 'gone'] },
      },
    };
    const { user } = renderPage();
    await openSettings(user);
    await user.click(await screen.findByText('Profile'));
    expect(await screen.findByText('Owner: admin')).toBeInTheDocument();
    const table = within(screen.getByRole('table'));
    expect(table.getByText('alpha')).toBeInTheDocument();
    expect(table.getByText('nightly')).toBeInTheDocument();
    expect(table.getByText('gone')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Change password/i })).toBeNull();
    await waitFor(() => expect(screen.getByText('Upload:')).toBeInTheDocument());
  });
});

describe('header', () => {
  const mobile = () =>
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query === '(max-width: 767px)',
          media: query,
          addEventListener: () => {},
          removeEventListener: () => {},
        }) as unknown as MediaQueryList,
    );

  const renderHeader = (props: Partial<Parameters<typeof Header>[0]> = {}) => {
    const handlers = { onCreateClick: vi.fn(), onMenuClick: vi.fn(), onSearchChange: vi.fn() };
    const utils = renderWithProviders(<Header title="Channels" createButtonText="Create channel" {...handlers} {...props} />);
    return { ...utils, ...handlers };
  };

  it('drives menu, create, search and settings on a phone', async () => {
    mobile();
    const { user, onCreateClick, onMenuClick, onSearchChange } = renderHeader();
    expect(screen.getByRole('heading', { name: 'Channels' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open menu' }));
    expect(onMenuClick).toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Create channel' }));
    expect(onCreateClick).toHaveBeenCalled();
    await user.type(screen.getByPlaceholderText('Search...'), 'st');
    expect(onSearchChange).toHaveBeenLastCalledWith('st');
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(onSearchChange).toHaveBeenLastCalledWith('');
    expect(screen.getByPlaceholderText('Search...')).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Settings' }));
    expect(await screen.findByText('Administrator')).toBeInTheDocument();
    await user.click(screen.getByText('Profile'));
    expect(await screen.findByRole('heading', { name: /Change password/i })).toBeInTheDocument();
  });

  it('shows custom title content and hides search and create when asked', () => {
    mobile();
    renderHeader({ titleContent: <span>custom title</span>, hideSearch: true, createButtonText: '' });
    expect(screen.getByText('custom title')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Channels' })).toBeNull();
    expect(screen.queryByPlaceholderText('Search...')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Create channel' })).toBeNull();
  });

  it('clears the desktop search', async () => {
    const { user, onSearchChange } = renderHeader();
    await user.type(screen.getByPlaceholderText('Search...'), 'x');
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(onSearchChange).toHaveBeenLastCalledWith('');
    expect(screen.queryByRole('button', { name: 'Clear search' })).toBeNull();
  });
});
