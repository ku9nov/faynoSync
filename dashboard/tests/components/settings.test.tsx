import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, lastCall, route, useFakeApi } from '../fakeApi';
import { currentLocation, pick } from '../helpers';
import { SettingsPage } from '@/pages/SettingsPage';

const perms = (overrides: Record<string, unknown> = {}) => ({
  Apps: { Create: true, Delete: false, Edit: true, Download: true, Upload: false, Allowed: ['app-1'] },
  Channels: { Create: false, Delete: false, Edit: false, Allowed: [] },
  Platforms: { Create: false, Delete: false, Edit: false, Allowed: [''] },
  Archs: { Create: false, Delete: false, Edit: false, Allowed: [] },
  ...overrides,
});

let users: { id: string; username: string; permissions: ReturnType<typeof perms>; updated_at: string }[];
let tokens: Record<string, unknown>[];

beforeEach(() => {
  useFakeApi();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  users = [{ id: 'tu-1', username: 'dev', permissions: perms(), updated_at: '' }];
  tokens = [
    { id: 't-old', name: 'old', token_prefix: 'fs_old', allowed_apps: ['app-2'], expires_at: null, created_at: '2025-01-01T00:00:00Z', last_used_at: null },
    { id: 't-new', name: 'new', token_prefix: 'fs_new', allowed_apps: ['app-1', 'gone'], expires_at: '2027-01-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z', last_used_at: null },
  ];
  server.use(
    route('get', '/users/list', () => HttpResponse.json({ users })),
    route('get', '/token/list', () => HttpResponse.json({ tokens })),
    route('get', '/tuf/v1/config', () => HttpResponse.json({})),
  );
});

const renderSettings = (path = '/settings') => renderWithProviders(<SettingsPage />, { route: path, path });
const userRow = () => screen.getByTitle('dev').closest('tr') as HTMLElement;

describe('settings tabs', () => {
  it('navigates between tabs', async () => {
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'CI/CD Tokens' }));
    expect(currentLocation()).toBe('/settings/tokens');
  });
});

describe('users', () => {
  it('shows permissions and allowed counts, ignoring blank ids', async () => {
    renderSettings();
    await screen.findByTitle('dev');
    const checkboxes = within(userRow()).getAllByRole('checkbox') as HTMLInputElement[];
    expect(checkboxes.slice(0, 5).map((c) => c.checked)).toEqual([true, false, true, true, false]);
    const counts = within(userRow()).getAllByRole('button').filter((b) => b.querySelector('.fa-search')).map((b) => b.textContent);
    expect(counts).toEqual(['1', '0', '0', '0']);
  });

  it('marks unsaved changes and saves the whole permission set', async () => {
    server.use(route('post', '/user/update', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    expect(within(userRow()).queryByTitle('Unsaved changes')).toBeNull();
    const checkboxes = within(userRow()).getAllByRole('checkbox');
    await user.click(checkboxes[1]);
    await user.click(checkboxes[5]);
    expect(within(userRow()).getByTitle('Unsaved changes')).toBeInTheDocument();

    const allowedButtons = within(userRow()).getAllByRole('button').filter((b) => b.querySelector('.fa-search'));
    await user.click(allowedButtons[1]);
    expect(screen.getByRole('heading', { name: 'Allowed Channels' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'nightly' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));

    await user.click(within(userRow()).getByTitle('Save user permissions'));
    await waitFor(() => expect(lastCall('POST', '/user/update')).toBeDefined());
    expect(lastCall('POST', '/user/update').json).toEqual({
      id: 'tu-1',
      username: 'dev',
      permissions: {
        apps: { create: true, delete: true, edit: true, download: true, upload: false, allowed: ['app-1'] },
        channels: { create: true, delete: false, edit: false, allowed: ['ch-2'] },
        platforms: { create: false, delete: false, edit: false, allowed: [''] },
        archs: { create: false, delete: false, edit: false, allowed: [] },
      },
    });
  });

  it('select all in the allowed modal picks every item', async () => {
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    const allowedButtons = within(userRow()).getAllByRole('button').filter((b) => b.querySelector('.fa-search'));
    await user.click(allowedButtons[3]);
    await user.click(screen.getByRole('button', { name: 'Select all' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    expect(allowedButtons[3]).toHaveTextContent('2');
  });

  it('renames a user and only sends a password when one is typed', async () => {
    server.use(route('post', '/user/update', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(within(userRow()).getByTitle('Edit user'));
    const name = screen.getByPlaceholderText('Enter username');
    expect(name).toHaveValue('dev');
    await user.clear(name);
    await user.type(name, 'developer');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(lastCall('POST', '/user/update')).toBeDefined());
    const body = lastCall('POST', '/user/update').json as Record<string, unknown>;
    expect(body.username).toBe('developer');
    expect(body).not.toHaveProperty('password');

    await user.click(within(userRow()).getByTitle('Edit user'));
    await user.type(screen.getByPlaceholderText('Enter new password'), 'n3w-passw0rd');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(callsTo('POST', '/user/update')).toHaveLength(2));
    expect((lastCall('POST', '/user/update').json as Record<string, unknown>).password).toBe('n3w-passw0rd');
  });

  it('deletes a user after typing the username', async () => {
    server.use(route('delete', '/user/delete', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(within(userRow()).getByTitle('Delete user'));
    const confirm = screen.getByRole('button', { name: 'Delete' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByPlaceholderText('Enter username'), 'dev');
    await user.click(confirm);
    await waitFor(() => expect(lastCall('DELETE', '/user/delete')?.json).toEqual({ id: 'tu-1' }));
  });

  it('creates a user with default permissions', async () => {
    server.use(route('post', '/user/create', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'Create User' }));
    const create = screen.getByRole('button', { name: 'Create user' });
    expect(create).toBeDisabled();
    await user.type(screen.getAllByPlaceholderText('Enter username').pop()!, 'qa');
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    const password = (document.querySelector('input[placeholder="Enter password"]') as HTMLInputElement).value;
    expect(password).toHaveLength(32);
    const appsSection = screen.getByRole('heading', { name: 'Apps' }).parentElement as HTMLElement;
    await user.click(within(appsSection).getByRole('checkbox', { name: 'Upload' }));
    await pick(user, 'Allowed apps', 'beta');
    await pick(user, 'Allowed channels', 'stable');
    await user.click(create);
    await waitFor(() => expect(lastCall('POST', '/user/create')).toBeDefined());
    expect(lastCall('POST', '/user/create').json).toEqual({
      username: 'qa',
      password,
      permissions: {
        apps: { create: false, delete: false, edit: false, download: false, upload: true, allowed: ['app-2'] },
        channels: { create: false, delete: false, edit: false, allowed: ['ch-1'] },
        platforms: { create: false, delete: false, edit: false, allowed: [] },
        archs: { create: false, delete: false, edit: false, allowed: [] },
      },
    });
  });

  it('keeps the create dialog open on error', async () => {
    server.use(route('post', '/user/create', () => HttpResponse.json({ error: 'exists' }, { status: 409 })));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'Create User' }));
    await user.type(screen.getAllByPlaceholderText('Enter username').pop()!, 'dev');
    await user.type(document.querySelector('input[placeholder="Enter password"]') as HTMLInputElement, 'pw123456');
    await user.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText(/status code 409/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Create user' })).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    users = [];
    renderSettings();
    expect(await screen.findByText('No users found')).toBeInTheDocument();
  });
});

describe('CI/CD tokens', () => {
  const renderTokens = () => renderSettings('/settings/tokens');

  it('lists tokens newest first with app names', async () => {
    renderTokens();
    await screen.findByText('fs_new');
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getAllByRole('cell')[0].textContent)).toEqual(['new', 'old']);
    expect(within(rows[0]).getByText('alpha, gone')).toBeInTheDocument();
    expect(within(rows[1]).getAllByText('Never').length).toBeGreaterThan(0);
  });

  it('validates before creating', async () => {
    const { user } = renderTokens();
    await screen.findByText('fs_new');
    await user.click(screen.getByRole('button', { name: /Create token/ }));
    expect(await screen.findByText('Token name is required')).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('GitHub Actions - MyApp'), 'ci');
    await user.click(screen.getByRole('button', { name: /Create token/ }));
    expect(await screen.findByText('Please select at least one allowed app')).toBeInTheDocument();
    expect(callsTo('POST', '/token/create')).toHaveLength(0);
  });

  it('creates a token, shows it once and refreshes the list', async () => {
    server.use(
      route('post', '/token/create', () => {
        tokens = [...tokens, { id: 't-3', name: 'ci', token_prefix: 'fs_ci', allowed_apps: ['app-1'], created_at: '2026-05-01T12:00:00Z' }];
        return HttpResponse.json({ ...tokens[2], token: 'fs_ci_full_secret' });
      }),
    );
    const { user } = renderTokens();
    await screen.findByText('fs_new');
    await user.type(screen.getByPlaceholderText('GitHub Actions - MyApp'), '  ci  ');
    await pick(user, 'Expiration', '7 days');
    await user.click(screen.getByRole('button', { name: 'Select allowed apps (0)' }));
    await user.click(screen.getByRole('checkbox', { name: 'alpha' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    expect(screen.getByRole('button', { name: 'Select allowed apps (1)' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Create token/ }));

    expect(await screen.findByText('fs_ci_full_secret')).toBeInTheDocument();
    const body = lastCall('POST', '/token/create').json as { name: string; allowed_apps: string[]; expires_at: string };
    expect(body.name).toBe('ci');
    expect(body.allowed_apps).toEqual(['app-1']);
    const sevenDays = 7 * 24 * 3600 * 1000;
    expect(Math.abs(Date.parse(body.expires_at) - Date.now() - sevenDays)).toBeLessThan(60_000);
    expect(await screen.findByText('fs_ci')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('GitHub Actions - MyApp')).toHaveValue('');
  });

  it('never-expiring tokens send no expiry', async () => {
    server.use(route('post', '/token/create', () => HttpResponse.json({ id: 'x', name: 'x', token_prefix: 'p', allowed_apps: [], created_at: '', token: 'tok' })));
    const { user } = renderTokens();
    await screen.findByText('fs_new');
    await user.type(screen.getByPlaceholderText('GitHub Actions - MyApp'), 'forever');
    await pick(user, 'Expiration', 'Never');
    await user.click(screen.getByRole('button', { name: 'Select allowed apps (0)' }));
    await user.click(screen.getByRole('button', { name: 'Select all' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    await user.click(screen.getByRole('button', { name: /Create token/ }));
    await waitFor(() => expect(lastCall('POST', '/token/create')).toBeDefined());
    expect(lastCall('POST', '/token/create').json).toEqual({ name: 'forever', allowed_apps: ['app-1', 'app-2'] });
  });

  it('revokes a token', async () => {
    server.use(
      route('delete', '/token/delete', () => {
        tokens = tokens.filter((t) => t.id !== 't-old');
        return HttpResponse.json({ message: 'Token revoked' });
      }),
    );
    const { user } = renderTokens();
    await screen.findByText('fs_old');
    const row = screen.getByText('fs_old').closest('tr') as HTMLElement;
    await user.click(within(row).getByTitle('Revoke token'));
    expect(await screen.findByText('Token revoked')).toBeInTheDocument();
    expect(lastCall('DELETE', '/token/delete').json).toEqual({ id: 't-old' });
    await waitFor(() => expect(screen.queryByText('fs_old')).toBeNull());
  });

  it('shows list errors', async () => {
    server.use(route('get', '/token/list', () => HttpResponse.json({ error: 'not allowed' }, { status: 403 })));
    renderTokens();
    expect(await screen.findByText('not allowed')).toBeInTheDocument();
    expect(screen.getByText('No tokens found')).toBeInTheDocument();
  });
});
