import { describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { API, server } from '../msw';
import { clearHistory, loadHistoryFromStorage, saveToHistory, updateHistoryStatus } from '@/components/settings/tuf/history';
import { deleteSigningMetadata } from '@/components/settings/tuf/deleteSigningMetadata';
import { generateTufKmsCommands } from '@/components/settings/tuf/generateTufKmsCommands';
import type { TufHistoryEntry } from '@/components/settings/tuf/types';

const entry = (overrides: Partial<TufHistoryEntry> = {}): Omit<TufHistoryEntry, 'id'> => ({
  timestamp: '2026-01-01T00:00:00Z',
  appName: 'app',
  operation: 'bootstrap',
  status: 'pending',
  taskId: 't1',
  ...overrides,
});

describe('TUF history', () => {
  it('starts empty and survives corrupt storage', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(loadHistoryFromStorage()).toEqual([]);
    localStorage.setItem('tuf-history', 'nope');
    expect(loadHistoryFromStorage()).toEqual([]);
    expect(error).toHaveBeenCalledWith('Failed to load TUF history:', expect.any(SyntaxError));
  });

  it('prepends entries with unique ids and caps at 20', () => {
    let history: TufHistoryEntry[] = [];
    for (let i = 0; i < 25; i++) history = saveToHistory(entry({ taskId: `t${i}` }), history);
    expect(history).toHaveLength(20);
    expect(history[0].taskId).toBe('t24');
    expect(new Set(history.map((h) => h.id)).size).toBe(20);
    expect(loadHistoryFromStorage()).toEqual(history);
  });

  it.each([
    ['SUCCESS', 'success'],
    ['FAILURE', 'failed'],
    ['PENDING', 'pending'],
  ] as const)('maps %s to %s for the matching task only', (state, status) => {
    let history = saveToHistory(entry({ taskId: 'a' }), []);
    history = saveToHistory(entry({ taskId: 'b' }), history);
    const updated = updateHistoryStatus('a', state, history, { message: 'done' });
    expect(updated.find((h) => h.taskId === 'a')).toMatchObject({ status, result: { message: 'done' } });
    expect(updated.find((h) => h.taskId === 'b')).toMatchObject({ status: 'pending' });
    expect(updated.find((h) => h.taskId === 'b')?.result).toBeUndefined();
    expect(loadHistoryFromStorage()).toEqual(updated);
  });

  it('clears', () => {
    saveToHistory(entry(), []);
    expect(clearHistory()).toEqual([]);
    expect(localStorage.getItem('tuf-history')).toBeNull();
  });
});

describe('deleteSigningMetadata', () => {
  const url = `${API}/tuf/v1/metadata/sign/delete`;

  it('validates input', async () => {
    await expect(deleteSigningMetadata({ appName: '', role: 'root' })).rejects.toThrow('App name is required');
    await expect(deleteSigningMetadata({ appName: 'a', role: '' })).rejects.toThrow('Role is required');
  });

  it('posts the role with the encoded app name and the auth token', async () => {
    localStorage.setItem('token', 'tok');
    let seen: { appName: string | null; body: unknown; auth: string | null } | undefined;
    server.use(
      http.post(url, async ({ request }) => {
        seen = {
          appName: new URL(request.url).searchParams.get('appName'),
          body: await request.json(),
          auth: request.headers.get('authorization'),
        };
        return HttpResponse.json({ message: 'accepted', data: { task_id: 'task-1', last_update: 'now' } });
      }),
    );
    await expect(deleteSigningMetadata({ appName: 'my app&x', role: 'root' })).resolves.toEqual({
      success: true,
      hasTask: true,
      message: 'accepted',
      taskId: 'task-1',
      lastUpdate: 'now',
    });
    expect(seen).toEqual({ appName: 'my app&x', body: { role: 'root' }, auth: 'Bearer tok' });
  });

  it('succeeds without a task', async () => {
    server.use(http.post(url, () => HttpResponse.json({})));
    await expect(deleteSigningMetadata({ appName: 'a', role: 'root' })).resolves.toEqual({
      success: true,
      hasTask: false,
      message: 'Signing metadata deleted successfully.',
    });
  });

  it('treats 404 as nothing to delete', async () => {
    server.use(http.post(url, () => HttpResponse.json({ message: 'nothing here' }, { status: 404 })));
    await expect(deleteSigningMetadata({ appName: 'a', role: 'root' })).resolves.toMatchObject({
      success: true,
      hasTask: false,
      message: 'nothing here',
    });
  });

  it('treats "not in a signing process" as success', async () => {
    server.use(
      http.post(url, () => HttpResponse.json({ error: 'role is not in a signing process' }, { status: 400 })),
    );
    await expect(deleteSigningMetadata({ appName: 'a', role: 'root' })).resolves.toMatchObject({
      success: true,
      hasTask: false,
      message: 'No signing process for root.',
    });
  });

  it('throws the server error otherwise', async () => {
    server.use(http.post(url, () => HttpResponse.json({ error: 'boom' }, { status: 500 })));
    await expect(deleteSigningMetadata({ appName: 'a', role: 'root' })).rejects.toThrow('boom');
  });
});

describe('generateTufKmsCommands', () => {
  const params = {
    appName: 'app',
    keyType: 'ED25519',
    roleName: 'targets',
    adminName: 'admin',
    expiration: { root: 365, timestamp: 1, snapshot: 7, targets: 30 },
    thresholds: { root: 2, timestamp: 1, snapshot: 1, targets: 1, delegation: 3 },
  };

  it('renders init and bootstrap commands', () => {
    expect(generateTufKmsCommands(params)).toBe(
      [
        "tuf-kms init \\\n  --app 'app' \\\n  --admin 'admin' \\\n  --key-type ed25519",
        "tuf-kms bootstrap generate \\\n  --role 'targets' \\\n" +
          '  --root-threshold 2 --root-expiration 365 \\\n' +
          '  --targets-threshold 1 --targets-expiration 30 \\\n' +
          '  --snapshot-threshold 1 --snapshot-expiration 7 \\\n' +
          '  --timestamp-threshold 1 --timestamp-expiration 1 \\\n' +
          '  --delegation-threshold 3',
      ].join('\n\n'),
    );
  });

  it('adds a trimmed metadata url and shell-quotes user values', () => {
    const out = generateTufKmsCommands({
      ...params,
      appName: "it's $(rm -rf /)",
      metadataUrl: '  https://cdn/x  ',
    });
    expect(out).toContain(`--app 'it'\\''s $(rm -rf /)'`);
    expect(out).toContain("--metadata-url 'https://cdn/x'");
  });

  it('omits a blank metadata url', () => {
    expect(generateTufKmsCommands({ ...params, metadataUrl: '   ' })).not.toContain('--metadata-url');
  });

  it('rejects unsupported key types', () => {
    expect(() => generateTufKmsCommands({ ...params, keyType: 'dsa' })).toThrow(/Unsupported key type/);
  });
});
