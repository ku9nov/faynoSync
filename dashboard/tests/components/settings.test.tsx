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

  it('builds every permission section, removes chips and copies the password', async () => {
    server.use(route('post', '/user/create', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'Create User' }));
    await user.type(screen.getAllByPlaceholderText('Enter username').pop()!, 'ops');
    await user.type(document.querySelector('input[placeholder="Enter password"]') as HTMLInputElement, 'pw-123456');
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy password' }));
    expect(writeText).toHaveBeenCalledWith('pw-123456');
    expect(await screen.findByText('Password copied to clipboard!')).toBeInTheDocument();

    const section = (name: string) => screen.getByRole('heading', { name }).parentElement as HTMLElement;
    await user.click(within(section('Channels')).getByRole('checkbox', { name: 'Create' }));
    await user.click(within(section('Platforms')).getByRole('checkbox', { name: 'Delete' }));
    await user.click(within(section('Architectures')).getByRole('checkbox', { name: 'Edit' }));
    const pickMany = async (name: string, ...options: string[]) => {
      await pick(user, name, options[0]);
      for (const option of options.slice(1)) {
        await user.click(within(screen.getByRole('listbox', { name })).getByRole('option', { name: option }));
      }
      await user.keyboard('{Escape}');
    };
    await pickMany('Allowed apps', 'alpha', 'beta');
    await pickMany('Allowed platforms', 'windows');
    await pickMany('Allowed architectures', 'arm64', 'amd64', 'amd64');
    expect(within(section('Apps')).getByText('alpha')).toBeInTheDocument();
    await user.click(within(within(section('Apps')).getByText('alpha')).getByRole('button', { name: 'Remove' }));
    expect(within(section('Platforms')).getByText('windows')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Create user' }));
    await waitFor(() => expect(lastCall('POST', '/user/create')).toBeDefined());
    expect(lastCall('POST', '/user/create').json).toEqual({
      username: 'ops',
      password: 'pw-123456',
      permissions: {
        apps: { create: false, delete: false, edit: false, download: false, upload: false, allowed: ['app-2'] },
        channels: { create: true, delete: false, edit: false, allowed: [] },
        platforms: { create: false, delete: true, edit: false, allowed: ['pl-2'] },
        archs: { create: false, delete: false, edit: true, allowed: ['ar-2'] },
      },
    });
  });

  it('cancels user creation without a request', async () => {
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'Create User' }));
    await user.type(screen.getAllByPlaceholderText('Enter username').pop()!, '   ');
    expect(screen.getByRole('button', { name: 'Create user' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('heading', { name: 'Create user' })).toBeNull();
    expect(callsTo('POST', '/user/create')).toHaveLength(0);
  });

  it('keeps the create dialog open on error', async () => {
    server.use(route('post', '/user/create', () => HttpResponse.json({ error: 'exists' }, { status: 409 })));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(screen.getByRole('button', { name: 'Create User' }));
    await user.type(screen.getAllByPlaceholderText('Enter username').pop()!, 'dev');
    await user.type(document.querySelector('input[placeholder="Enter password"]') as HTMLInputElement, 'pw123456');
    await user.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText('exists')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Create user' })).toBeInTheDocument();
  });

  it('edits allowed apps, platforms and architectures through the picker', async () => {
    server.use(route('post', '/user/update', () => HttpResponse.json({})));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    const allowed = () => within(userRow()).getAllByRole('button').filter((b) => b.querySelector('.fa-search'));
    await user.click(allowed()[0]);
    expect(screen.getByRole('heading', { name: 'Allowed Apps' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'alpha' }));
    await user.click(screen.getByRole('checkbox', { name: 'beta' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    await user.click(allowed()[2]);
    expect(screen.getByRole('heading', { name: 'Allowed Platforms' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'linux' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    await user.click(allowed()[3]);
    await user.click(screen.getByRole('checkbox', { name: 'arm64' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    expect(allowed().map((b) => b.textContent)).toEqual(['1', '0', '1', '1']);
    await user.click(within(userRow()).getByTitle('Save user permissions'));
    await waitFor(() => expect(lastCall('POST', '/user/update')).toBeDefined());
    const sent = (lastCall('POST', '/user/update').json as { permissions: Record<string, { allowed: string[] }> }).permissions;
    expect(sent.apps.allowed).toEqual(['app-2']);
    expect(sent.platforms.allowed).toEqual(['pl-1']);
    expect(sent.archs.allowed).toEqual(['ar-2']);
  });

  it('fills in a permission category the user never had', async () => {
    server.use(route('post', '/user/update', () => HttpResponse.json({})));
    const { Archs: _archs, ...withoutArchs } = perms();
    users = [{ id: 'tu-1', username: 'dev', permissions: withoutArchs as ReturnType<typeof perms>, updated_at: '' }];
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    const checkboxes = within(userRow()).getAllByRole('checkbox');
    await user.click(checkboxes[checkboxes.length - 1]);
    await user.click(within(userRow()).getByTitle('Save user permissions'));
    await waitFor(() => expect(lastCall('POST', '/user/update')).toBeDefined());
    expect((lastCall('POST', '/user/update').json as { permissions: { archs: unknown } }).permissions.archs).toEqual({
      create: false,
      delete: false,
      edit: true,
      allowed: [],
    });
  });

  it('keeps unsaved changes and tells the user when saving permissions fails', async () => {
    server.use(route('post', '/user/update', () => HttpResponse.json({ error: 'permission store unavailable' }, { status: 500 })));
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(within(userRow()).getAllByRole('checkbox')[1]);
    await user.click(within(userRow()).getByTitle('Save user permissions'));
    expect(await screen.findByText('permission store unavailable')).toBeInTheDocument();
    expect(within(userRow()).getByTitle('Unsaved changes')).toBeInTheDocument();
  });

  it('shows rename and delete failures inside their dialogs', async () => {
    server.use(
      route('post', '/user/update', () => HttpResponse.json({ error: 'taken' }, { status: 409 })),
      route('delete', '/user/delete', () => HttpResponse.json({ error: 'cannot delete yourself' }, { status: 400 })),
    );
    const { user } = renderSettings();
    await screen.findByTitle('dev');
    await user.click(within(userRow()).getByTitle('Edit user'));
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy password' }));
    expect(writeText).toHaveBeenCalledWith((screen.getByPlaceholderText('Enter new password') as HTMLInputElement).value);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('taken')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    await user.click(within(userRow()).getByTitle('Delete user'));
    await user.type(screen.getByPlaceholderText('Enter username'), 'dev');
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('cannot delete yourself')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Delete user' })).toBeInTheDocument();
  });

  it('shows a list error', async () => {
    server.use(route('get', '/users/list', () => HttpResponse.json({}, { status: 500 })));
    renderSettings();
    expect(await screen.findByText('Error loading users data')).toBeInTheDocument();
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

  const fillToken = async (user: ReturnType<typeof renderTokens>['user']) => {
    await screen.findByText('fs_new');
    await user.type(screen.getByPlaceholderText('GitHub Actions - MyApp'), 'ci');
    await user.click(screen.getByRole('button', { name: 'Select allowed apps (0)' }));
    await user.click(screen.getByRole('checkbox', { name: 'beta' }));
    await user.click(screen.getByRole('button', { name: 'Update list' }));
    await user.click(screen.getByRole('button', { name: /Create token/ }));
  };

  it('copies the freshly created token', async () => {
    server.use(route('post', '/token/create', () => HttpResponse.json({ id: 'x', name: 'ci', token_prefix: 'p', allowed_apps: [], created_at: '', token: 'fs_full' })));
    const { user } = renderTokens();
    await fillToken(user);
    await screen.findByText('fs_full');
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: /Copy token/ }));
    expect(writeText).toHaveBeenCalledWith('fs_full');
    expect(await screen.findByText('Token copied to clipboard')).toBeInTheDocument();
  });

  it.each([
    ['an error in a 200 body', () => HttpResponse.json({ error: 'quota reached' }), 'quota reached'],
    ['a body without the token', () => HttpResponse.json({ id: 'x' }), 'Token was created, but response is invalid'],
    ['an HTTP error message', () => HttpResponse.json({ message: 'app not owned' }, { status: 403 }), 'app not owned'],
  ])('reports create failure from %s', async (_, resolver, text) => {
    server.use(route('post', '/token/create', resolver));
    const { user } = renderTokens();
    await fillToken(user);
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Copy token/ })).toBeNull();
    expect(screen.getByPlaceholderText('GitHub Actions - MyApp')).toHaveValue('ci');
  });

  it.each([
    ['an error in a 200 body', () => HttpResponse.json({ error: 'token in use' }), 'token in use'],
    ['an HTTP error', () => HttpResponse.json({ error: 'forbidden' }, { status: 403 }), 'forbidden'],
  ])('reports revoke failure from %s', async (_, resolver, text) => {
    server.use(route('delete', '/token/delete', resolver));
    const { user } = renderTokens();
    await screen.findByText('fs_old');
    await user.click(within(screen.getByText('fs_old').closest('tr') as HTMLElement).getByTitle('Revoke token'));
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.getByText('fs_old')).toBeInTheDocument();
  });

  it('shows "-" for tokens without apps and refreshes on demand', async () => {
    tokens = [{ id: 't-1', name: 'none', token_prefix: 'fs_none', allowed_apps: [], expires_at: null, created_at: '2026-01-01T00:00:00Z', last_used_at: null }];
    const { user } = renderTokens();
    const row = (await screen.findByText('fs_none')).closest('tr') as HTMLElement;
    expect(within(row).getByText('-')).toBeInTheDocument();
    const before = callsTo('GET', '/token/list').length;
    await user.click(screen.getByTitle('Refresh tokens list'));
    await waitFor(() => expect(callsTo('GET', '/token/list').length).toBe(before + 1));
  });

  it('treats a list without tokens as empty', async () => {
    server.use(route('get', '/token/list', () => HttpResponse.json({})));
    renderTokens();
    expect(await screen.findByText('No tokens found')).toBeInTheDocument();
  });

  it('shows list errors', async () => {
    server.use(route('get', '/token/list', () => HttpResponse.json({ error: 'not allowed' }, { status: 403 })));
    renderTokens();
    expect(await screen.findByText('not allowed')).toBeInTheDocument();
    expect(screen.getByText('No tokens found')).toBeInTheDocument();
  });
});
