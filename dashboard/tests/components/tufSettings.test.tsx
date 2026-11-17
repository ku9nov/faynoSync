import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, lastCall, route, useFakeApi } from '../fakeApi';
import { pick } from '../helpers';
import { TufSettings } from '@/components/settings/TufSettings';

type BootstrapState = Record<string, unknown>;
let bootstrapState: BootstrapState;

const config = {
  bootstrap: 'bs-1',
  role_expiration: 1,
  root_expiration: 365,
  root_num_keys: 3,
  root_threshold: 2,
  snapshot_expiration: 7,
  snapshot_num_keys: 1,
  snapshot_threshold: 1,
  targets_expiration: 30,
  targets_num_keys: 1,
  targets_online_key: 1,
  targets_threshold: 1,
  timestamp_expiration: 1,
  timestamp_num_keys: 1,
  timestamp_threshold: 1,
};

const done: BootstrapState = { bootstrap: true, state: null, id: 'bs-1', redis_locks: { bootstrap_lock: 'lock' } };

// TufSettings schedules task checks 1s after an action; cleared here so a finished test's timers
// cannot write its history into the next test's localStorage.
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  useFakeApi();
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  bootstrapState = { bootstrap: false };
  server.use(
    route('get', '/tuf/v1/bootstrap', () => HttpResponse.json({ data: bootstrapState, message: 'Bootstrap completed' })),
    route('get', '/tuf/v1/config', () => HttpResponse.json({ data: config })),
    route('get', '/tuf/v1/task', ({ request }) =>
      HttpResponse.json({ data: { task_id: new URL(request.url).searchParams.get('task_id'), state: 'SUCCESS', result: { message: 'ok' } } }),
    ),
  );
});

const renderTuf = async () => {
  const utils = renderWithProviders(<TufSettings />);
  await pick(utils.user, 'App', 'beta');
  return utils;
};

describe('TUF app selection', () => {
  it('offers only TUF-enabled apps', async () => {
    const { user } = renderWithProviders(<TufSettings />);
    await user.click(await screen.findByRole('combobox', { name: 'App' }));
    const options = screen.getAllByRole('option').map((o) => o.textContent);
    expect(options).toContain('beta');
    expect(options).not.toContain('alpha');
  });

  it('checks bootstrap status for the picked app', async () => {
    await renderTuf();
    await waitFor(() => expect(lastCall('GET', '/tuf/v1/bootstrap')?.query.get('appName')).toBe('beta'));
  });
});

describe('offline key generation', () => {
  it('builds tuf-kms commands with the owner as admin', async () => {
    const { user } = await renderTuf();
    await user.click(screen.getByRole('heading', { name: /Step 1: Generate TUF Root Keys/ }));
    await pick(user, 'Key type', 'ecdsa');
    await user.type(screen.getByPlaceholderText(/Enter role name/), 'targets');
    await user.type(screen.getByPlaceholderText('https://s3.example.com/tuf_metadata'), 'https://cdn/tuf');
    await user.click(screen.getByRole('button', { name: 'Generate Commands' }));
    expect(await screen.findByText('Commands generated successfully!')).toBeInTheDocument();
    const commands = screen.getByText(/tuf-kms init/).textContent!;
    expect(commands).toContain("--app 'beta'");
    expect(commands).toContain("--admin 'admin'");
    expect(commands).toContain('--key-type ecdsa');
    expect(commands).toContain("--metadata-url 'https://cdn/tuf'");
    expect(commands).toContain('--root-threshold 2 --root-expiration 364');
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'generate', appName: 'beta' });
  });
});

describe('bootstrap', () => {
  const pastePayload = async (user: Awaited<ReturnType<typeof renderTuf>>['user'], text: string) => {
    await user.click(await screen.findByRole('radio', { name: 'Use custom payload' }));
    const area = screen.getByPlaceholderText('Paste JSON payload here...');
    await user.clear(area);
    await user.click(area);
    await user.paste(text);
  };

  it('rejects empty and invalid payloads without calling the API', async () => {
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('radio', { name: 'Use custom payload' }));
    await user.click(screen.getByRole('button', { name: /Start Bootstrap/ }));
    expect(screen.getByText('Custom payload is required')).toBeInTheDocument();
    await pastePayload(user, '{not json');
    await user.click(screen.getByRole('button', { name: /Start Bootstrap/ }));
    expect(screen.getByText('Invalid JSON format')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/bootstrap')).toHaveLength(0);
  });

  it('posts the parsed payload and tracks the task', async () => {
    server.use(
      route('post', '/tuf/v1/bootstrap', () => {
        bootstrapState = { bootstrap: true, state: 'PENDING', task_id: 'boot-1' };
        return HttpResponse.json({ data: { task_id: 'boot-1', last_update: '2026-01-01T00:00:00Z' } });
      }),
    );
    const { user } = await renderTuf();
    const payload = { settings: { roles: { root: { threshold: 2 } } }, metadata: { root: { signed: {} } } };
    await pastePayload(user, JSON.stringify(payload));
    await user.click(screen.getByRole('button', { name: /Start Bootstrap/ }));
    expect(await screen.findByText('TUF bootstrap started successfully!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/bootstrap').json).toEqual(payload);
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({
      operation: 'bootstrap',
      taskId: 'boot-1',
      appName: 'beta',
    });
    await waitFor(() => expect(lastCall('GET', '/tuf/v1/task')?.query.get('task_id')).toBe('boot-1'), { timeout: 3000 });
  });

  it('reports a failed bootstrap', async () => {
    server.use(route('post', '/tuf/v1/bootstrap', () => HttpResponse.json({ message: 'keys missing' }, { status: 400 })));
    const { user } = await renderTuf();
    await pastePayload(user, '{}');
    await user.click(screen.getByRole('button', { name: /Start Bootstrap/ }));
    expect(await screen.findByText('keys missing')).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'bootstrap', status: 'failed' });
  });
});

describe('bootstrap status', () => {
  it('hides bootstrap and shows update/rotation once bootstrapped', async () => {
    bootstrapState = done;
    await renderTuf();
    expect(await screen.findByRole('heading', { name: 'Update' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Rotation' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Start Bootstrap/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Recovery' })).toBeNull();
  });

  it('offers recovery when the Redis bootstrap lock is gone', async () => {
    bootstrapState = { bootstrap: true, state: null, id: 'bs-1', redis_locks: {} };
    server.use(
      route('post', '/tuf/v1/bootstrap/recovery', () => {
        bootstrapState = done;
        return HttpResponse.json({ message: 'Recovered', data: { task_id: 'rec-1' } });
      }),
    );
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('button', { name: 'Recovery' }));
    expect(await screen.findByText('Recovered')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/bootstrap/recovery').json).toEqual({ appName: 'beta' });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Recovery' })).toBeNull());
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'bootstrap-recovery', taskId: 'rec-1' });
  });

  it('shows a pending bootstrap as in progress', async () => {
    bootstrapState = { bootstrap: true, state: 'PENDING', task_id: 'boot-2' };
    await renderTuf();
    expect(await screen.findByText(/Starting Bootstrap/)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Update' })).toBeNull();
  });

  it('surfaces status errors', async () => {
    server.use(route('get', '/tuf/v1/bootstrap', () => HttpResponse.json({ message: 'redis down' }, { status: 503 })));
    await renderTuf();
    expect(await screen.findByText('redis down')).toBeInTheDocument();
  });
});

describe('config', () => {
  it('shows the server config and submits new expirations', async () => {
    bootstrapState = done;
    server.use(route('put', '/tuf/v1/config', () => HttpResponse.json({ data: { task_id: 'cfg-1' } })));
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('heading', { name: /Update tuf config/i }));
    expect(await screen.findByText('Configuration Details')).toBeInTheDocument();
    expect(screen.getByText('Root Threshold').nextElementSibling).toHaveTextContent('2');
    const [targets, snapshot] = screen.getAllByRole('spinbutton');
    expect(targets).toHaveValue(30);
    await user.clear(targets);
    await user.type(targets, '45');
    await user.clear(snapshot);
    await user.type(snapshot, '9');
    await user.click(screen.getByRole('button', { name: /Update Config/ }));
    expect(await screen.findByText('Config update submitted successfully!')).toBeInTheDocument();
    const call = lastCall('PUT', '/tuf/v1/config');
    expect(call.query.get('appName')).toBe('beta');
    expect(call.json).toEqual({ settings: { expiration: { targets: 45, snapshot: 9, timestamp: 1 } } });
  });

  it('refreshes online metadata for the picked roles', async () => {
    bootstrapState = done;
    server.use(route('post', '/tuf/v1/metadata/online', () => HttpResponse.json({ data: { task_id: 'meta-1' } })));
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('heading', { name: /Update tuf config/i }));
    await screen.findByText('Configuration Details');
    await user.click(screen.getAllByRole('checkbox', { name: 'Timestamp' })[0]);
    await user.click(screen.getAllByRole('checkbox', { name: 'Snapshot' })[0]);
    await user.click(screen.getAllByRole('button', { name: /Update Metadata/ })[0]);
    expect(await screen.findByText('Metadata update submitted successfully for timestamp, snapshot!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/online').json).toEqual({ roles: ['timestamp', 'snapshot'] });
  });
});

describe('history', () => {
  it('lists saved operations and clears them', async () => {
    localStorage.setItem(
      'tuf-history',
      JSON.stringify([{ id: '1', timestamp: '2026-01-01T00:00:00Z', appName: 'beta', operation: 'publish', status: 'pending', taskId: 'pub-1' }]),
    );
    const { user } = renderWithProviders(<TufSettings />);
    expect(await screen.findByText('publish')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Clear/ }));
    expect(await screen.findByText('No history yet')).toBeInTheDocument();
    expect(localStorage.getItem('tuf-history')).toBeNull();
  });
});

describe('bootstrap progress', () => {
  it('polls a pending bootstrap every 5s until it succeeds', async () => {
    bootstrapState = { bootstrap: true, state: 'PENDING', task_id: 'boot-3' };
    await renderTuf();
    await screen.findByText(/Starting Bootstrap/);
    const before = callsTo('GET', '/tuf/v1/bootstrap').length;
    bootstrapState = { bootstrap: true, state: 'SUCCESS', task_id: 'boot-3', result: { last_update: '2026-11-16T08:00:00Z' } };
    vi.advanceTimersByTime(5000);
    await waitFor(() => expect(callsTo('GET', '/tuf/v1/bootstrap').length).toBe(before + 1));
    expect(await screen.findByRole('heading', { name: 'Update' })).toBeInTheDocument();
    vi.advanceTimersByTime(10_000);
    await new Promise((r) => setTimeout(r, 20));
    expect(callsTo('GET', '/tuf/v1/bootstrap').length).toBe(before + 1);
  });

  it('shows a failed bootstrap task as an error', async () => {
    bootstrapState = { bootstrap: true, state: 'FAILURE', task_id: 'boot-4', result: { message: 'signing failed' } };
    await renderTuf();
    expect(await screen.findByText('error', { selector: 'span.capitalize' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Start Bootstrap/ })).toBeEnabled();
    expect(screen.queryByRole('heading', { name: 'Update' })).toBeNull();
  });

  it('reports an invalid bootstrap response', async () => {
    server.use(route('post', '/tuf/v1/bootstrap', () => HttpResponse.json({ data: {} })));
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('radio', { name: 'Use custom payload' }));
    await user.click(screen.getByPlaceholderText('Paste JSON payload here...'));
    await user.paste('{}');
    await user.click(screen.getByRole('button', { name: /Start Bootstrap/ }));
    expect(await screen.findByText('Invalid response: missing task_id')).toBeInTheDocument();
  });

  it('reports a failed recovery', async () => {
    bootstrapState = { bootstrap: true, state: null, id: '', redis_locks: { bootstrap_lock: 'x' } };
    server.use(route('post', '/tuf/v1/bootstrap/recovery', () => HttpResponse.json({ message: 'nothing to recover' }, { status: 409 })));
    const { user } = await renderTuf();
    await user.click(await screen.findByRole('button', { name: 'Recovery' }));
    expect(await screen.findByText('nothing to recover')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Recovery' })).toBeInTheDocument();
  });
});

describe('config failures', () => {
  beforeEach(() => {
    bootstrapState = done;
  });

  const openConfig = async () => {
    const utils = await renderTuf();
    await utils.user.click(await screen.findByRole('heading', { name: /Update tuf config/i }));
    await screen.findByText('Configuration Details');
    return utils;
  };

  it('shows a config load error', async () => {
    server.use(route('get', '/tuf/v1/config', () => HttpResponse.json({ message: 'config missing' }, { status: 404 })));
    await renderTuf();
    expect(await screen.findByText('config missing')).toBeInTheDocument();
  });

  it.each([
    ['an HTTP error', () => HttpResponse.json({ message: 'expiry too long' }, { status: 400 }), 'expiry too long'],
    ['a response without task', () => HttpResponse.json({ data: {} }), 'Invalid response: missing task_id'],
  ])('records a config update failure from %s', async (_, resolver, text) => {
    server.use(route('put', '/tuf/v1/config', resolver));
    const { user } = await openConfig();
    await user.click(screen.getByRole('button', { name: /Update Config/ }));
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'update-config', status: 'failed' });
  });

  it('reloads the config after a successful update', async () => {
    server.use(route('put', '/tuf/v1/config', () => HttpResponse.json({ data: { task_id: 'cfg-2' } })));
    const { user } = await openConfig();
    const loads = callsTo('GET', '/tuf/v1/config').length;
    await user.click(screen.getByRole('button', { name: /Update Config/ }));
    await screen.findByText('Config update submitted successfully!');
    vi.advanceTimersByTime(1000);
    await waitFor(() => expect(callsTo('GET', '/tuf/v1/config').length).toBe(loads + 1));
  });

  it('records a metadata refresh failure and names all roles when none is picked', async () => {
    server.use(route('post', '/tuf/v1/metadata/online', () => HttpResponse.json({ error: 'timestamp key offline' }, { status: 500 })));
    const { user } = await openConfig();
    await user.click(screen.getAllByRole('button', { name: /Update Metadata/ })[0]);
    expect(await screen.findByText('timestamp key offline')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/online').json).toEqual({ roles: [] });
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'metadata-update', status: 'failed' });
  });
});

describe('history tasks', () => {
  const entry = (overrides: Record<string, unknown> = {}) => ({
    id: '1',
    timestamp: '2026-01-01T00:00:00Z',
    appName: 'beta',
    operation: 'publish',
    status: 'pending',
    taskId: 'pub-9',
    ...overrides,
  });

  it('checks pending tasks on its own and shows their result', async () => {
    localStorage.setItem('tuf-history', JSON.stringify([entry()]));
    const { user } = renderWithProviders(<TufSettings />);
    await waitFor(() => expect(lastCall('GET', '/tuf/v1/task')?.query.get('task_id')).toBe('pub-9'));
    expect(screen.queryByText('TUF task loaded successfully!')).toBeNull();
    await user.click(await screen.findByTitle('View task result'));
    expect(screen.getByRole('heading', { name: 'Task Result' })).toBeInTheDocument();
    expect(screen.getByText(/"message": "ok"/)).toBeInTheDocument();
    await user.click(screen.getByTitle('Close'));
    expect(screen.queryByRole('heading', { name: 'Task Result' })).toBeNull();
  });

  it('checks a task on demand and reports failures', async () => {
    localStorage.setItem('tuf-history', JSON.stringify([entry({ status: 'success' })]));
    const { user } = renderWithProviders(<TufSettings />);
    await user.click(await screen.findByTitle('Check task status'));
    expect(await screen.findByText('TUF task loaded successfully!')).toBeInTheDocument();
    server.use(route('get', '/tuf/v1/task', () => HttpResponse.json({ message: 'task expired' }, { status: 404 })));
    await user.click(screen.getByTitle('Check task status'));
    expect(await screen.findByText('task expired')).toBeInTheDocument();
  });

  it('shows "-" for entries without a task or result', async () => {
    localStorage.setItem('tuf-history', JSON.stringify([entry({ taskId: undefined, status: 'failed' })]));
    renderWithProviders(<TufSettings />);
    const row = (await screen.findByText('publish')).closest('tr') as HTMLElement;
    expect(within(row).queryByRole('button')).toBeNull();
    expect(within(row).getAllByText('-').length).toBeGreaterThan(0);
  });
});
