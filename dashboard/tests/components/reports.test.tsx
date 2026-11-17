import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, lastCall, route, useFakeApi } from '../fakeApi';
import { pick } from '../helpers';
import { ReportsPage } from '@/pages/ReportsPage';

type Group = Record<string, unknown> & { group_hash: string; status: string };

const group = (hash: string, overrides: Partial<Group> = {}): Group => ({
  id: `id-${hash}`,
  group_hash: hash,
  app_id: 'app-1',
  application: { name: 'alpha', version: '1.2.3', channel: 'stable' },
  system: { platform: 'linux', arch: 'amd64' },
  event: { type: 'update_failure', reason: 'checksum_mismatch' },
  stats: { count: 42, first_seen: '2026-01-01T10:00:00Z', last_seen: '2026-01-02T10:00:00Z', details_stored: 2, details_rejected: 0 },
  status: 'open',
  tags: ['net'],
  note: 'tracked in JIRA-1',
  created_at: '2026-01-01T10:00:00Z',
  updated_at: '2026-01-02T10:00:00Z',
  ...overrides,
});

let groups: Group[];

beforeEach(() => {
  useFakeApi();
  groups = [group('h1'), group('h2', { status: 'muted', tags: [], note: '', stats: { count: 1, first_seen: 'x', last_seen: 'x', details_stored: 0, details_rejected: 0 } })];
  server.use(
    route('get', '/reports/groups', ({ request }) => {
      const status = new URL(request.url).searchParams.get('status');
      const items = groups.filter((g) => status === 'all' || g.status === status);
      return HttpResponse.json({ items, total: items.length, page: 1, limit: 20 });
    }),
  );
});

const renderPage = () => renderWithProviders(<ReportsPage />, { route: '/reports', path: '/reports' });
const row = (text: string) => screen.getByText(text).closest('tr') as HTMLElement;

describe('reports page', () => {
  it('lists open groups by default with readable labels', async () => {
    renderPage();
    expect(await screen.findByText('Update Failure')).toBeInTheDocument();
    expect(screen.getByText('Checksum Mismatch')).toBeInTheDocument();
    expect(screen.getByText('v1.2.3 · stable')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('net')).toBeInTheDocument();
    expect(screen.getByText('tracked in JIRA-1')).toBeInTheDocument();
    expect(screen.getByText('1 group total')).toBeInTheDocument();
    expect(lastCall('GET', '/reports/groups').query.get('status')).toBe('open');
    expect(lastCall('GET', '/reports/groups').query.get('limit')).toBe('20');
  });

  it('switches status tabs', async () => {
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(screen.getByRole('button', { name: 'Muted' }));
    await waitFor(() => expect(lastCall('GET', '/reports/groups').query.get('status')).toBe('muted'));
    expect(await screen.findByText('1 group total')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'All' }));
    expect(await screen.findByText('2 groups total')).toBeInTheDocument();
  });

  it('sends filters and clears them', async () => {
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await pick(user, 'Application', 'alpha');
    await pick(user, 'Event Type', 'crash');
    await user.type(screen.getByPlaceholderText('e.g. 1.4.2'), '1.2.3');
    await user.type(screen.getByPlaceholderText('e.g. checksum_mismatch'), 'oom');
    await waitFor(() =>
      expect(Object.fromEntries(lastCall('GET', '/reports/groups').query)).toMatchObject({
        app: 'alpha',
        type: 'crash',
        version: '1.2.3',
        reason: 'oom',
        status: 'open',
      }),
    );
    groups = [];
    await user.click(screen.getByRole('button', { name: 'Clear all' }));
    await waitFor(() => {
      const q = lastCall('GET', '/reports/groups').query;
      expect(['app', 'type', 'version', 'reason'].filter((k) => q.has(k))).toEqual([]);
    });
    expect(await screen.findByText('No reports available yet')).toBeInTheDocument();
  });

  it('says when filters match nothing', async () => {
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    groups = [];
    await user.type(screen.getByPlaceholderText('e.g. 1.4.2'), '9');
    expect(await screen.findByText('No reports match the selected filters')).toBeInTheDocument();
  });

  it.each([
    ['Resolve', 'resolved', 'Group marked as resolved'],
    ['Mute', 'muted', 'Group marked as muted'],
  ])('%s sends the new status', async (button, status, toast) => {
    server.use(route('patch', '/reports/groups/h1', () => HttpResponse.json({ group_hash: 'h1', status })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    expect(within(row('Update Failure')).queryByTitle('Reopen')).toBeNull();
    await user.click(within(row('Update Failure')).getByTitle(button));
    expect(await screen.findByText(toast)).toBeInTheDocument();
    expect(lastCall('PATCH', '/reports/groups/h1').json).toEqual({ status });
  });

  it('reopens a muted group and shows errors', async () => {
    server.use(route('patch', '/reports/groups/h2', () => HttpResponse.json({ error: 'read only' }, { status: 403 })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(screen.getByRole('button', { name: 'Muted' }));
    await waitFor(() => expect(screen.getAllByText('Muted').length).toBeGreaterThan(1));
    const muted = screen.getAllByRole('row')[1];
    expect(within(muted).queryByTitle('Mute')).toBeNull();
    await user.click(within(muted).getByTitle('Reopen'));
    expect(await screen.findByText('read only')).toBeInTheDocument();
    expect(lastCall('PATCH', '/reports/groups/h2').json).toEqual({ status: 'open' });
  });

  it('edits tags and note', async () => {
    server.use(route('patch', '/reports/groups/h1', () => HttpResponse.json({})));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle('Edit tags & note'));
    const tagInput = screen.getByPlaceholderText('Type a tag and press Enter');
    await user.type(tagInput, 'Disk{Enter}');
    await user.type(tagInput, 'net,');
    await user.click(screen.getAllByTitle('Remove tag')[0]);
    await user.type(tagInput, 'later');
    const note = screen.getByPlaceholderText('e.g. tracked in JIRA-123');
    await user.clear(note);
    await user.type(note, '  fixed in 1.2.4  ');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Report group updated')).toBeInTheDocument();
    expect(lastCall('PATCH', '/reports/groups/h1').json).toEqual({ tags: ['disk', 'later'], note: 'fixed in 1.2.4' });
  });

  it('deletes a group', async () => {
    server.use(route('delete', '/reports/groups/h1', () => HttpResponse.json({ group_hash: 'h1', deleted: true })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle('Delete permanently'));
    expect(screen.getByRole('heading', { name: 'Delete report group' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('Report group deleted')).toBeInTheDocument();
    expect(callsTo('DELETE', '/reports/groups/h1')).toHaveLength(1);
  });

  it('opens stored detail blobs', async () => {
    server.use(
      route('get', '/reports/groups/h1/blobs', () =>
        HttpResponse.json({
          items: [
            {
              id: 'b1',
              group_hash: 'h1',
              storage: { driver: 's3', key: 'reports/h1/b1.json.gz', compressed_size: 1024, decompressed_size: 4096, content_type: 'application/json', encoding: 'gzip' },
              created_at: '2026-01-01T00:00:00Z',
              expires_at: '2026-01-01T01:00:00Z',
              url: 'https://s3/b1?sig',
            },
          ],
        }),
      ),
    );
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle('View 2 stored detail blobs'));
    expect(await screen.findByText('reports/h1/b1.json.gz')).toBeInTheDocument();
    expect(screen.getByText('4.0 KB decompressed')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download' })).toHaveAttribute('href', 'https://s3/b1?sig');
  });

  it('paginates', async () => {
    groups = Array.from({ length: 45 }, (_, i) => group(`p${i}`));
    server.use(
      route('get', '/reports/groups', ({ request }) => {
        const page = Number(new URL(request.url).searchParams.get('page'));
        return HttpResponse.json({ items: groups.slice((page - 1) * 20, page * 20), total: 45, page, limit: 20 });
      }),
    );
    const { user } = renderPage();
    expect(await screen.findByText('Page 1 of 3')).toBeInTheDocument();
    await user.click(screen.getByTitle('Last page'));
    expect(await screen.findByText('Page 3 of 3')).toBeInTheDocument();
    expect(lastCall('GET', '/reports/groups').query.get('page')).toBe('3');
  });
  it('filters by the last-seen window', async () => {
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.type(screen.getByPlaceholderText('Start date'), '2026-01-02 10:00');
    await waitFor(() => expect(lastCall('GET', '/reports/groups').query.get('from')).toBe(new Date(2026, 0, 2, 10, 0).toISOString()));
    await user.type(screen.getByPlaceholderText('End date'), '2026-01-05 18:30');
    await waitFor(() => expect(lastCall('GET', '/reports/groups').query.get('to')).toBe(new Date(2026, 0, 5, 18, 30).toISOString()));
    await user.clear(screen.getByPlaceholderText('Start date'));
    await waitFor(() => expect(lastCall('GET', '/reports/groups').query.has('from')).toBe(false));
  });

  it('shows who resolved a group and when', async () => {
    groups = [group('h3', { status: 'resolved', resolved_by: 'admin', resolved_at: '2026-01-03T12:00:00Z' })];
    const { user } = renderPage();
    await user.click(await screen.findByRole('button', { name: 'Resolved' }));
    expect(await screen.findByText('by admin')).toBeInTheDocument();
  });

  it.each([
    ['update', 'patch', 'Edit tags & note', 'Save', 'Failed to update report group'],
    ['delete', 'delete', 'Delete permanently', 'Delete', 'Failed to delete report group'],
  ] as const)('keeps the %s dialog open on failure', async (_, method, title, button, fallback) => {
    server.use(route(method, '/reports/groups/h1', () => HttpResponse.json({ message: 'group locked' }, { status: 409 })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle(title));
    await user.click(screen.getByRole('button', { name: button }));
    expect(await screen.findByText(/group locked/)).toBeInTheDocument();
    expect(screen.queryByText(fallback)).toBeNull();
    expect(screen.getByRole('button', { name: button })).toBeInTheDocument();
  });

  it('copies a presigned blob link', async () => {
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
    const items = [
      {
        id: 'b1',
        group_hash: 'h1',
        storage: { driver: 's3', key: 'k1', compressed_size: 10, decompressed_size: 10, content_type: 'application/json', encoding: 'gzip' },
        created_at: '2026-01-01T00:00:00Z',
        expires_at: '2026-01-01T01:00:00Z',
        url: 'https://s3/b1?sig',
      },
    ];
    server.use(route('get', '/reports/groups/h1/blobs', () => HttpResponse.json({ items })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle('View 2 stored detail blobs'));
    await screen.findByText('k1');
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy presigned link' }));
    expect(writeText).toHaveBeenCalledWith('https://s3/b1?sig');
    const header = screen.getByRole('heading', { name: 'Report details' }).parentElement as HTMLElement;
    await user.click(within(header).getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('heading', { name: 'Report details' })).toBeNull();
    Reflect.deleteProperty(window, 'isSecureContext');
  });

  it('says when a group has no stored blobs', async () => {
    server.use(route('get', '/reports/groups/h1/blobs', () => HttpResponse.json({ items: [] })));
    const { user } = renderPage();
    await screen.findByText('Update Failure');
    await user.click(within(row('Update Failure')).getByTitle('View 2 stored detail blobs'));
    expect(await screen.findByText('No detail blobs available for this group')).toBeInTheDocument();
  });
});
