import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { API } from '../msw';
import { callsTo, db, lastCall, route, useFakeApi, version } from '../fakeApi';
import { currentLocation, pick } from '../helpers';
import { HomePage } from '@/pages/HomePage';

const renderApp = (name = 'alpha', search = '') =>
  renderWithProviders(<HomePage />, { route: `/applications/${name}${search}`, path: '/applications/:appName' });

const versionCard = (v: string) => screen.getByTitle(`Version ${v}`).closest('.sharedCard') as HTMLElement;

beforeEach(() => {
  useFakeApi();
  db.versions = [version('1'), version('2', { Channel: 'nightly', Published: false, Critical: true })];
});

describe('version list', () => {
  it('shows versions with their status badges and changelog', async () => {
    renderApp();
    expect(await screen.findByTitle('Version 1.0.1')).toBeInTheDocument();
    const v1 = versionCard('1.0.1');
    expect(within(v1).getByText('Published')).toBeInTheDocument();
    expect(within(v1).getByText('stable')).toBeInTheDocument();
    expect(within(v1).getByText('Changes for 1')).toBeInTheDocument();
    const v2 = versionCard('1.0.2');
    expect(within(v2).getByText('Not published')).toBeInTheDocument();
    expect(within(v2).getByText('Critical')).toBeInTheDocument();
    expect(lastCall('GET', '/search').query.get('app_name')).toBe('alpha');
    expect(lastCall('GET', '/search').query.get('limit')).toBe('9');
  });

  it('shows the empty state', async () => {
    db.versions = [];
    renderApp();
    expect(await screen.findByText('No versions have been uploaded yet.')).toBeInTheDocument();
  });

  it('goes back to the list', async () => {
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(currentLocation()).toBe('/applications');
  });

  it('sends filters to the search and resets them', async () => {
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await pick(user, 'Channel', 'nightly');
    await pick(user, 'Platform', 'linux');
    await pick(user, 'Architecture', 'arm64');
    await pick(user, 'Publication status', 'Not published');
    await pick(user, 'Critical status', 'Critical');
    await waitFor(() => {
      const q = lastCall('GET', '/search').query;
      expect(Object.fromEntries(q)).toMatchObject({
        channel: 'nightly',
        platform: 'linux',
        arch: 'arm64',
        published: 'false',
        critical: 'true',
      });
    });
    await user.click(screen.getByRole('button', { name: 'Reset Filters' }));
    await waitFor(() => {
      const q = lastCall('GET', '/search').query;
      expect(['channel', 'platform', 'arch', 'published', 'critical'].filter((k) => q.has(k))).toEqual([]);
    });
    expect(screen.queryByRole('button', { name: 'Reset Filters' })).toBeNull();
  });

  it('paginates through the page query param', async () => {
    db.versions = Array.from({ length: 20 }, (_, i) => version(String(i + 1)));
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    expect(screen.getByTitle('Previous page')).toBeDisabled();
    await user.click(screen.getByTitle('Next page'));
    expect(await screen.findByTitle('Version 1.0.10')).toBeInTheDocument();
    expect(currentLocation()).toBe('/applications/alpha?page=2');
    await user.click(screen.getByTitle('Last page'));
    expect(await screen.findByTitle('Version 1.0.19')).toBeInTheDocument();
    expect(screen.getByTitle('Next page')).toBeDisabled();
    expect(lastCall('GET', '/search').query.get('page')).toBe('3');
  });

  it('opens the full changelog', async () => {
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(within(versionCard('1.0.1')).getByRole('button', { name: 'View full changelog' }));
    expect(screen.getByRole('heading', { name: 'Changelog' })).toBeInTheDocument();
    expect(screen.getByText(/alpha v1\.0\.1/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('heading', { name: 'Changelog' })).toBeNull();
  });

  it('marks a version without a changelog', async () => {
    db.versions = [version('1', { Changelog: [] })];
    renderApp();
    expect(await screen.findByText('Changelog not provided')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'View full changelog' })).toBeNull();
  });

  it('flags an incomplete staged rollout', async () => {
    db.versions = [version('1', { RolloutPercent: 25 })];
    renderApp();
    expect(await screen.findByText('Rollout 25%')).toBeInTheDocument();
  });
});

describe('downloads', () => {
  it('opens the signed url returned for a single artifact', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    server.use(route('get', '/download/1.bin', () => HttpResponse.json({ download_url: 'https://cdn/signed' })));
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(within(versionCard('1.0.1')).getByRole('button', { name: 'Download' }));
    await waitFor(() => expect(open).toHaveBeenCalledWith('https://cdn/signed', '_blank', 'noopener,noreferrer'));
  });

  it('reports a missing artifact', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    server.use(route('get', '/download/1.bin', () => HttpResponse.json({}, { status: 404 })));
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(within(versionCard('1.0.1')).getByRole('button', { name: 'Download' }));
    expect(await screen.findByText('Download is not available')).toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
  });

  it('lists artifacts when there are several', async () => {
    db.versions = [
      version('1', {
        Artifacts: [
          { ID: 'a', link: `${API}/download/a.deb`, platform: 'linux', arch: 'amd64', package: '.deb' },
          { ID: 'b', link: `${API}/download/b.exe`, platform: 'windows', arch: 'amd64', package: '.exe' },
        ],
      }),
    ];
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    server.use(route('get', '/download/b.exe', () => HttpResponse.json({ download_url: 'https://cdn/b' })));
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(within(versionCard('1.0.1')).getByRole('button', { name: 'Download' }));
    expect(screen.getByRole('heading', { name: 'Download artifact' })).toBeInTheDocument();
    await user.click(screen.getByText(`${API}/download/b.exe`));
    await waitFor(() => expect(open).toHaveBeenCalledWith('https://cdn/b', '_blank', 'noopener,noreferrer'));
  });

  it('summarises artifacts per platform', async () => {
    db.versions = [
      version('1', {
        Artifacts: [
          { ID: 'a', link: 'x', platform: 'linux', arch: 'amd64', package: '.deb' },
          { ID: 'b', link: 'y', platform: 'linux', arch: 'arm64', package: '.rpm' },
          { ID: 'c', link: 'z', platform: 'windows', arch: 'amd64', package: '.exe' },
        ],
      }),
    ];
    renderApp();
    await screen.findByTitle('Version 1.0.1');
    expect(screen.getByTitle('Artifacts: linux(2) windows(1)')).toBeInTheDocument();
    expect(screen.getByText('linux/arm64 - .rpm')).toBeInTheDocument();
  });
});

describe('delete one version', () => {
  it('requires the version string and deletes by id', async () => {
    server.use(route('delete', '/apps/delete', () => HttpResponse.json({ deleteAppResult: 1 })));
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(within(versionCard('1.0.1')).getByRole('button', { name: 'Delete' }));
    const form = screen.getByPlaceholderText('Enter current version').closest('form') as HTMLElement;
    const confirm = within(form).getByRole('button', { name: 'Delete' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByPlaceholderText('Enter current version'), '1.0.1');
    await user.click(confirm);
    await waitFor(() => expect(screen.queryByText('Delete confirmation')).toBeNull());
    expect(lastCall('DELETE', '/apps/delete').query.getAll('id')).toEqual(['1']);
  });
});

describe('bulk delete', () => {
  beforeEach(() => {
    db.versions = Array.from({ length: 12 }, (_, i) =>
      version(String(i + 1), { Channel: i % 2 ? 'nightly' : 'stable' }),
    );
  });

  const deleteHandler = (respond?: (ids: string[]) => Response | undefined) =>
    route('delete', '/apps/delete', ({ request }) => {
      const ids = new URL(request.url).searchParams.getAll('id');
      const custom = respond?.(ids);
      if (custom) return custom;
      db.versions = db.versions.filter((v) => !ids.includes(v.ID as string));
      return HttpResponse.json({ deleted: ids.length });
    });

  it('selects the page, requires the app name and deletes', async () => {
    server.use(deleteHandler());
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    expect(screen.getByText('0 selected')).toBeInTheDocument();
    await user.click(versionCard('1.0.1'));
    await user.click(within(versionCard('1.0.2')).getByRole('checkbox'));
    expect(screen.getByText('2 selected')).toBeInTheDocument();
    await user.click(versionCard('1.0.1'));
    expect(screen.getByText('1 selected')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Select all on page' }));
    expect(screen.getByText('9 selected')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Delete 9 versions' }));
    expect(screen.getByText(/To delete 9 versions of "alpha"/)).toBeInTheDocument();
    const confirm = screen.getByRole('button', { name: 'Delete 9' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(confirm);

    expect(await screen.findByText('Deleted 9 versions')).toBeInTheDocument();
    expect(callsTo('DELETE', '/apps/delete')).toHaveLength(1);
    expect(lastCall('DELETE', '/apps/delete').query.getAll('id')).toHaveLength(9);
    await waitFor(() => expect(screen.queryByTitle('Version 1.0.1')).toBeNull());
    expect(screen.queryByText(/selected$/)).toBeNull();
  });

  it('selects every matching version across pages and deletes them in chunks', async () => {
    server.use(deleteHandler());
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    await user.click(screen.getByRole('button', { name: 'Select all 12 matching filters' }));
    expect(await screen.findByText('12 selected')).toBeInTheDocument();
    expect(lastCall('GET', '/search').query.get('limit')).toBe('12');

    await user.click(screen.getByRole('button', { name: 'Delete 12 versions' }));
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Delete 12' }));

    expect(await screen.findByText('Deleted 12 versions')).toBeInTheDocument();
    expect(callsTo('DELETE', '/apps/delete').map((c) => c.query.getAll('id').length)).toEqual([10, 2]);
  });

  it('shrinks chunks to the server limit', async () => {
    server.use(
      deleteHandler((ids) =>
        ids.length > 4 ? HttpResponse.json({ error: 'too many', limit: 4 }, { status: 400 }) : undefined,
      ),
    );
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    await user.click(screen.getByRole('button', { name: 'Select all on page' }));
    await user.click(screen.getByRole('button', { name: 'Delete 9 versions' }));
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Delete 9' }));
    expect(await screen.findByText('Deleted 9 versions')).toBeInTheDocument();
    expect(callsTo('DELETE', '/apps/delete').map((c) => c.query.getAll('id').length)).toEqual([9, 4, 4, 1]);
  });

  it('reports a partial failure and orphaned artifacts', async () => {
    let call = 0;
    server.use(
      route('delete', '/apps/delete', () => {
        call++;
        if (call === 1) return HttpResponse.json({ orphaned_links: ['s3://bucket/a.bin'] });
        return HttpResponse.json({ error: 'permission denied', forbidden: ['1.0.11'] }, { status: 403 });
      }),
    );
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    await user.click(screen.getByRole('button', { name: 'Select all 12 matching filters' }));
    await screen.findByText('12 selected');
    await user.click(screen.getByRole('button', { name: 'Delete 12 versions' }));
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Delete 12' }));

    expect(await screen.findByRole('heading', { name: 'Deletion report' })).toBeInTheDocument();
    expect(screen.getByText('Deleted 10 of 12 versions of "alpha".')).toBeInTheDocument();
    expect(screen.getAllByText('permission denied - forbidden: 1.0.11').length).toBeGreaterThan(0);
    expect(screen.getByText('2 versions were left untouched.')).toBeInTheDocument();
    expect(screen.getByText('s3://bucket/a.bin')).toBeInTheDocument();
    expect(screen.getByText('2 selected')).toBeInTheDocument();
  });

  it('keeps the dialog open to list orphaned artifacts after a clean delete', async () => {
    server.use(
      route('delete', '/apps/delete', () => HttpResponse.json({ orphaned_links: ['s3://bucket/left.bin'] })),
    );
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    await user.click(versionCard('1.0.1'));
    await user.click(screen.getByRole('button', { name: 'Delete 1 version' }));
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Delete 1' }));
    expect(await screen.findByRole('heading', { name: 'Deletion report' })).toBeInTheDocument();
    expect(screen.getByText('1 orphaned artifact')).toBeInTheDocument();
    expect(screen.getByText('s3://bucket/left.bin')).toBeInTheDocument();
  });

  it('cancelling selection clears it', async () => {
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'Select' }));
    await user.click(screen.getByRole('button', { name: 'Select all on page' }));
    await user.click(screen.getByRole('button', { name: 'Cancel selection' }));
    expect(screen.queryByText('9 selected')).toBeNull();
    expect(within(versionCard('1.0.1')).getByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });
});

describe('TUF apps', () => {
  const tufArtifacts = (signed: boolean[]) =>
    signed.map((s, i) => ({
      ID: `t${i}`,
      link: `l${i}`,
      platform: 'linux',
      arch: 'amd64',
      package: '.bin',
      TufTaskID: s ? 'task' : null,
      TufSigned: s,
    }));

  beforeEach(() => {
    db.apps = db.apps.map((a) => (a.AppName === 'alpha' ? { ...a, Tuf: true } : a));
  });

  it.each([
    [[true, true], 'TUF signed', false],
    [[true, false], 'TUF partial', true],
    [[false], 'TUF unsigned', true],
  ])('%j -> %s', async (signed, label, canSign) => {
    db.versions = [version('1', { Artifacts: tufArtifacts(signed) })];
    renderApp();
    expect(await screen.findByText(label)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Sign remaining artifacts/ }) !== null).toBe(canSign);
  });

  it('ignores updater feeds when computing the status', async () => {
    db.versions = [
      version('1', {
        Artifacts: [...tufArtifacts([true]), { ID: 'f', link: 'f', platform: 'linux', arch: 'amd64', package: '.yml', IsFeed: true, TufSigned: false, TufTaskID: null }],
      }),
    ];
    renderApp();
    expect(await screen.findByText('TUF signed')).toBeInTheDocument();
  });

  it('publishes unsigned artifacts and records the task', async () => {
    db.versions = [version('1', { Artifacts: tufArtifacts([false]) })];
    server.use(
      route('post', '/tuf/v1/artifacts/publish', () =>
        HttpResponse.json({ data: { task_id: 'task-9', last_update: '2026-01-01T00:00:00Z' } }),
      ),
    );
    const { user } = renderApp();
    await user.click(await screen.findByRole('button', { name: /Sign remaining artifacts/ }));
    expect(await screen.findByText('TUF artifacts publishing successfully started for version 1.0.1')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/artifacts/publish').json).toEqual({ app_id: 'app-1', version: '1.0.1' });
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({
      appName: 'alpha',
      operation: 'publish',
      status: 'pending',
      taskId: 'task-9',
    });
  });

  it('shows the publish error', async () => {
    db.versions = [version('1', { Artifacts: tufArtifacts([false]) })];
    server.use(route('post', '/tuf/v1/artifacts/publish', () => HttpResponse.json({ message: 'no keys' }, { status: 500 })));
    const { user } = renderApp();
    await user.click(await screen.findByRole('button', { name: /Sign remaining artifacts/ }));
    expect(await screen.findByText('no keys')).toBeInTheDocument();
    expect(localStorage.getItem('tuf-history')).toBeNull();
  });
});

describe('report key', () => {
  beforeEach(() => {
    server.use(
      route('get', '/report-keys/list', () =>
        HttpResponse.json({
          report_keys: [
            { id: 'k0', app_id: 'app-2', app_name: 'beta', key_value: 'old-key', updated_at: '2025-01-01T00:00:00Z' },
            { id: 'k1', app_id: 'app-2', app_name: 'beta', key_value: 'rk-123', updated_at: '2026-01-01T00:00:00Z' },
          ],
        }),
      ),
    );
  });

  it('shows the newest key for apps with reports', async () => {
    renderApp('beta');
    expect(await screen.findByText('rk-123')).toBeInTheDocument();
    expect(screen.queryByText('old-key')).toBeNull();
  });

  it('is hidden for apps without reports', async () => {
    renderApp('alpha');
    await screen.findByTitle('Version 1.0.1');
    expect(screen.queryByText('Report key')).toBeNull();
  });

  it('regenerates only after confirmation', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    server.use(route('post', '/report-keys/regenerate', () => HttpResponse.json({})));
    const { user } = renderApp('beta');
    await screen.findByText('rk-123');
    await user.click(screen.getByRole('button', { name: 'Regenerate report key' }));
    expect(callsTo('POST', '/report-keys/regenerate')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Regenerate report key' }));
    expect(await screen.findByText('Report key regenerated')).toBeInTheDocument();
    expect(lastCall('POST', '/report-keys/regenerate').json).toEqual({ app_id: 'app-2' });
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it('copies the key', async () => {
    const { user } = renderApp('beta');
    await screen.findByText('rk-123');
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy report key' }));
    expect(writeText).toHaveBeenCalledWith('rk-123');
    expect(await screen.findByText('Report key copied')).toBeInTheDocument();
  });
});

describe('download tokens (private apps)', () => {
  it('lists one row per channel and reveals a generated token', async () => {
    server.use(
      route('get', '/download-tokens/list', () =>
        HttpResponse.json({
          download_tokens: [
            { id: 't1', app_id: 'app-2', app_name: 'beta', channel_id: 'ch-1', channel_name: 'stable', token_prefix: 'dt_ab', updated_at: '2026-01-01T00:00:00Z' },
          ],
        }),
      ),
      route('post', '/download-tokens/regenerate', () => HttpResponse.json({ app_id: 'app-2', channel_id: 'ch-2', token: 'dt_full_secret' })),
    );
    const { user } = renderApp('beta');
    expect(await screen.findByText('Download tokens')).toBeInTheDocument();
    expect(await screen.findByText('dt_ab…')).toBeInTheDocument();
    const nightlyRow = screen.getByText('nightly').closest('div')!.parentElement as HTMLElement;
    await user.click(within(nightlyRow).getByRole('button', { name: 'Generate' }));
    expect(await screen.findByText('dt_full_secret')).toBeInTheDocument();
    expect(lastCall('POST', '/download-tokens/regenerate').json).toEqual({ app_id: 'app-2', channel_id: 'ch-2' });
  });

  it('asks before replacing an existing token', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    server.use(
      route('post', '/download-tokens/regenerate', () => HttpResponse.json({ app_id: 'app-2', channel_id: 'ch-1', token: 'new' })),
      route('get', '/download-tokens/list', () =>
        HttpResponse.json({
          download_tokens: [
            { id: 't1', app_id: 'app-2', app_name: 'beta', channel_id: 'ch-1', channel_name: 'stable', token_prefix: 'dt_ab', updated_at: '2026-01-01T00:00:00Z' },
          ],
        }),
      ),
    );
    const { user } = renderApp('beta');
    await user.click(await screen.findByRole('button', { name: 'Regenerate' }));
    expect(confirm).toHaveBeenCalled();
    expect(callsTo('POST', '/download-tokens/regenerate')).toHaveLength(0);
  });

  it('skips tokens for unlisted apps', async () => {
    db.apps = db.apps.map((a) => (a.AppName === 'beta' ? { ...a, DownloadMode: 'unlisted' } : a));
    renderApp('beta');
    expect(await screen.findByText(/This app is unlisted/)).toBeInTheDocument();
    expect(callsTo('GET', '/download-tokens/list')).toHaveLength(0);
  });
});

describe('CI upload command', () => {
  it('builds the script once every default is picked', async () => {
    const { user } = renderApp();
    await screen.findByTitle('Version 1.0.1');
    await user.click(screen.getByRole('button', { name: 'CI command' }));
    const dialog = screen.getByRole('heading', { name: 'CI upload command' }).closest('div')!.parentElement as HTMLElement;
    expect(within(dialog).getByText('Select channel, platform, architecture to generate the script.')).toBeInTheDocument();
    await pick(user, 'Channel', 'nightly');
    await pick(user, 'Platform', 'windows');
    expect(screen.getByRole('combobox', { name: 'Updater' })).toHaveTextContent('squirrel_windows (default)');
    await pick(user, 'Architecture', 'amd64');
    await user.click(screen.getByRole('checkbox', { name: 'Critical' }));
    const script = screen.getByText(/#!\/usr\/bin\/env bash/);
    expect(script.textContent).toContain("APP_NAME='alpha'");
    expect(script.textContent).toContain('--channel nightly --platform windows --arch amd64 --updater squirrel_windows --no-publish --critical');
    expect(script.textContent).toContain("API='http://localhost:3000'");
  });

  it('hides public-feed updaters for private apps', async () => {
    db.platforms = [{ ID: 'p', PlatformName: 'windows', Updated_at: '', Updaters: [{ type: 'squirrel_windows', default: true }] }];
    const { user } = renderApp('beta');
    await screen.findByText('Download tokens');
    await user.click(screen.getByRole('button', { name: 'CI command' }));
    await pick(user, 'Channel', 'stable');
    await pick(user, 'Platform', 'windows');
    await pick(user, 'Architecture', 'amd64');
    expect(screen.queryByRole('combobox', { name: 'Updater' })).toBeNull();
    expect(screen.getByText(/Every updater of this platform is unavailable for private apps/)).toBeInTheDocument();
    expect(screen.queryByText(/#!\/usr\/bin\/env bash/)).toBeNull();
  });
});
