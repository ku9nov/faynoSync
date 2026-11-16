import { beforeEach, describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { db, lastCall, route, useFakeApi } from '../fakeApi';
import { currentLocation } from '../helpers';
import { ChannelsPage } from '@/pages/ChannelsPage';
import { PrivateRoute } from '@/route/PrivateRoute';

beforeEach(() => useFakeApi());

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
