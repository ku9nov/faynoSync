import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, db, lastCall, route, useFakeApi, version } from '../fakeApi';
import { pick } from '../helpers';
import { StatisticsPage } from '@/pages/StatisticsPage';

const telemetry = (overrides: Record<string, unknown> = {}) => ({
  date: '2026-03-01',
  admin: 'admin',
  summary: { total_requests: 12345, unique_clients: 100, clients_using_latest_version: 70, clients_outdated: 30, total_active_apps: 2 },
  daily_stats: [
    { date: '2026-02-28', total_requests: 100, unique_clients: 10, clients_using_latest_version: 5, clients_outdated: 5 },
    { date: '2026-03-01', total_requests: 200, unique_clients: 20, clients_using_latest_version: 10, clients_outdated: 10 },
  ],
  versions: {
    used_versions_count: 2,
    known_versions: ['1.0.0', '2.0.0'],
    usage: [
      { version: '1.0.0', client_count: 30 },
      { version: '2.0.0', client_count: 70 },
    ],
  },
  platforms: [{ platform: 'linux', client_count: 100 }],
  architectures: [{ arch: 'amd64', client_count: 100 }],
  channels: [{ channel: 'stable', client_count: 100 }],
  ...overrides,
});

let adoption: Record<string, { usage: { version: string; client_count: number }[]; unique: number }>;

beforeEach(() => {
  useFakeApi();
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  adoption = {};
  server.use(
    route('get', '/telemetry', ({ request }) => {
      const params = new URL(request.url).searchParams;
      const app = params.get('apps');
      if (app && adoption[app]) {
        return HttpResponse.json(
          telemetry({
            summary: { total_requests: 0, unique_clients: adoption[app].unique, clients_using_latest_version: 0, clients_outdated: 0, total_active_apps: 1 },
            versions: { used_versions_count: 0, known_versions: [], usage: adoption[app].usage },
          }),
        );
      }
      return HttpResponse.json(telemetry());
    }),
  );
});

const renderPage = () => renderWithProviders(<StatisticsPage />, { route: '/statistics', path: '/statistics' });
const statValue = (title: string) => screen.getByText(title).nextElementSibling?.textContent;

describe('statistics page', () => {
  it('shows summary cards and version share', async () => {
    renderPage();
    expect(await screen.findByText('Total Requests')).toBeInTheDocument();
    expect(statValue('Total Requests')).toBe('12345');
    expect(statValue('Unique Clients')).toBe('100');
    expect(statValue('Latest Version Users')).toBe('70');
    expect(statValue('Outdated Clients')).toBe('30');
    expect(statValue('Active Apps')).toBe('2');
    const table = within(screen.getByText('Version Details').parentElement as HTMLElement);
    expect(table.getByText('70.0%')).toBeInTheDocument();
    expect(table.getByText('30.0%')).toBeInTheDocument();
  });

  it('asks for today by default and switches ranges', async () => {
    const { user } = renderPage();
    await screen.findByText('Total Requests');
    const today = new Date().toISOString().split('T')[0];
    expect(lastCall('GET', '/telemetry').query.get('date')).toBe(today);
    await user.click(screen.getByRole('button', { name: 'Last Week' }));
    await waitFor(() => expect(lastCall('GET', '/telemetry').query.get('range')).toBe('week'));
    await user.click(screen.getByRole('button', { name: 'Last Month' }));
    await waitFor(() => expect(lastCall('GET', '/telemetry').query.get('range')).toBe('month'));
  });

  it('sends multi-select filters joined by commas and removes them', async () => {
    const { user } = renderPage();
    await screen.findByText('Total Requests');
    await pick(user, 'Channels', 'stable');
    await pick(user, 'Channels', 'nightly');
    await pick(user, 'Platforms', 'linux');
    await waitFor(() => {
      const q = callsTo('GET', '/telemetry').filter((c) => !c.query.has('apps')).pop()!.query;
      expect(q.get('channels')).toBe('stable,nightly');
      expect(q.get('platforms')).toBe('linux');
    });
    await user.click(screen.getByRole('button', { name: 'Remove stable' }));
    await waitFor(() => {
      const q = callsTo('GET', '/telemetry').filter((c) => !c.query.has('apps')).pop()!.query;
      expect(q.get('channels')).toBe('nightly');
    });
  });

  it('shows the empty state when telemetry has nothing', async () => {
    server.use(route('get', '/telemetry', () => HttpResponse.json(null)));
    renderPage();
    expect(await screen.findByText('No Data Available')).toBeInTheDocument();
  });

  it('measures rollout adoption against the eligible pool', async () => {
    db.versions = [
      version('a', { Version: '1.5.0', Channel: 'stable' }),
      version('b', { Version: '2.0.0', Channel: 'stable', RolloutPercent: 25 }),
    ];
    adoption.alpha = {
      unique: 100,
      usage: [
        { version: '1.0.0', client_count: 60 },
        { version: '1.5.0', client_count: 20 },
        { version: '2.0.0', client_count: 20 },
      ],
    };
    renderPage();
    expect(await screen.findByText('Rollout Health')).toBeInTheDocument();
    const rowEl = (await screen.findByText('v2.0.0')).closest('div[class*="p-4"]') as HTMLElement;
    const row = within(rowEl);
    expect(row.getByText('alpha')).toBeInTheDocument();
    expect(row.getByText('25%')).toBeInTheDocument();
    expect(row.getByText('50.0%')).toBeInTheDocument();
    expect(row.getByText('20 of 40 eligible clients on this version or newer.')).toBeInTheDocument();
    expect(row.getByTitle('Target 25%')).toHaveStyle({ left: '25%' });
  });

  it('marks a rollout version nobody runs yet', async () => {
    db.versions = [version('b', { Version: '3.0.0', Channel: 'stable', RolloutPercent: 10 })];
    adoption.alpha = { unique: 50, usage: [{ version: '2.0.0', client_count: 50 }] };
    renderPage();
    const rowEl = (await screen.findByText('v3.0.0')).closest('div[class*="p-4"]') as HTMLElement;
    expect(within(rowEl).getByText('—')).toBeInTheDocument();
    expect(within(rowEl).getByText('No telemetry for this version in the selected period.')).toBeInTheDocument();
  });

  it('hides fully rolled out versions and idle apps', async () => {
    db.versions = [version('a', { Version: '2.0.0', RolloutPercent: 100 }), version('b', { Version: '2.1.0', RolloutPercent: 50 })];
    adoption.alpha = { unique: 0, usage: [] };
    renderPage();
    await screen.findByText('Total Requests');
    await waitFor(() => expect(callsTo('GET', '/telemetry').some((c) => c.query.get('apps') === 'alpha')).toBe(true));
    expect(screen.queryByText('Rollout Health')).toBeNull();
    expect(screen.queryByText('v2.0.0')).toBeNull();
  });
});
