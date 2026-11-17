import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, lastCall, route, useFakeApi } from '../fakeApi';
import { pick } from '../helpers';
import { RotateRootKeys } from '@/components/settings/tuf/RotateRootKeys';
import { RotateRoleKeys } from '@/components/settings/tuf/RotateRoleKeys';
import { RotateDelegatedKeys } from '@/components/settings/tuf/RotateDelegatedKeys';
import type { UserEvent } from '@testing-library/user-event';

const root = {
  signed: { version: 5, expires: '2027-01-01T00:00:00Z', keys: { a: {} }, roles: { root: { keyids: ['a'], threshold: 1 } } },
  signatures: [],
};

// Submit and delete schedule a task check 1s later; cleared so it cannot fire into the next test.
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  useFakeApi();
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json({ data: { trusted_root: root } })));
});

const paste = async (user: UserEvent, el: HTMLElement, text: string) => {
  await user.clear(el);
  await user.click(el);
  await user.paste(text);
};

const setNumber = async (user: UserEvent, el: HTMLElement, value: string) => {
  await user.tripleClick(el);
  await user.keyboard(value);
};

const props = () => ({ selectedApp: 'beta', isBootstrapSuccess: true, onSaveToHistory: vi.fn(), onCheckTufTasks: vi.fn() });
const pre = (text: RegExp) => screen.getByText(text, { selector: 'pre' }).textContent;
const paragraph = (text: string) =>
  screen.getByText((_, el) => el?.tagName === 'P' && el.textContent?.replace(/\s+/g, ' ').trim() === text);
const signStatus = (body: object, status = 200) =>
  server.use(route('get', '/tuf/v1/metadata/sign', () => HttpResponse.json(body, { status })));
const signResponse = (body: object, status = 200) =>
  server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json(body, { status })));
const deleteResponse = (body: object, status = 200) =>
  server.use(route('post', '/tuf/v1/metadata/sign/delete', () => HttpResponse.json(body, { status })));

describe('RotateRootKeys', () => {
  const open = async () => {
    const p = props();
    const utils = renderWithProviders(<RotateRootKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Root Keys' }));
    return { ...utils, ...p };
  };

  it('builds the rotate command from key count and expiry', async () => {
    const { user } = await open();
    const [count, days] = screen.getAllByRole('spinbutton');
    expect(pre(/tuf-kms rotate root/)).toBe('tuf-kms rotate root \\\n  --keys 2 \\\n  --root-expires 364');
    await setNumber(user, count, '3');
    await setNumber(user, days, '30');
    expect(pre(/tuf-kms rotate root/)).toBe('tuf-kms rotate root \\\n  --keys 3 \\\n  --root-expires 30');
  });

  it('submits the new root and records the task', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ data: { task_id: 'rot-1' } })));
    const { user, onSaveToHistory } = await open();
    const newRoot = { signed: { ...root.signed, version: 6 } };
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), JSON.stringify(newRoot));
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('Metadata submitted successfully!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata').json).toEqual({ metadata: { root: newRoot } });
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'root-meta-update', taskId: 'rot-1' }));
  });

  it('breaks threshold progress into old and new keys', async () => {
    server.use(
      route('post', '/tuf/v1/metadata/sign', () =>
        HttpResponse.json(
          {
            error:
              'not enough signatures. Progress: 1/4 signatures collected (1 old + 0 new). 3 more required (1 old + 2 new). Old keys signed: [aaaaaaaaaaaa]. Missing old keys: [bbbbbbbbbbbb]. Missing new keys: [cccccccccccc dddddddddddd].',
          },
          { status: 400 },
        ),
      ),
    );
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"aaaaaaaaaaaa","sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('1 / 4')).toBeInTheDocument();
    expect(screen.getByText('3 more signatures required')).toBeInTheDocument();
    expect(screen.getByText('1 more needed')).toBeInTheDocument();
    expect(screen.getByText('2 more needed')).toBeInTheDocument();
    expect(screen.getByText('aaaaaaaa...')).toBeInTheDocument();
    expect(screen.getByText('bbbbbbbb...')).toBeInTheDocument();
    expect(screen.getByText('dddddddd...')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign').json).toEqual({ role: 'root', signature: { keyid: 'aaaaaaaaaaaa', sig: 's' } });
  });

  it('finishes when the server has nothing pending', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ error: 'No metadata pending signing available' }, { status: 404 })));
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"a","sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('Metadata update finished! Root keys rotation completed successfully.')).toBeInTheDocument();
  });

  it('refuses signatures without keyid/sig', async () => {
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(screen.getAllByText('Signature must contain keyid and sig fields').length).toBeGreaterThan(0);
    expect(callsTo('POST', '/tuf/v1/metadata/sign')).toHaveLength(0);
  });
});

describe('RotateRoleKeys', () => {
  const open = async () => {
    const p = { ...props(), onUpdateMetadata: vi.fn() };
    const utils = renderWithProviders(<RotateRoleKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Top-Level Role Keys' }));
    return { ...utils, ...p };
  };

  it('builds the command and keeps threshold within the key count', async () => {
    const { user } = await open();
    expect(pre(/tuf-kms rotate role/)).toBe('tuf-kms rotate role timestamp \\\n  --keys 1 \\\n  --threshold 1');
    await pick(user, 'Role', 'snapshot');
    const [count, threshold, days] = screen.getAllByRole('spinbutton');
    await setNumber(user, count, '3');
    await setNumber(user, threshold, '3');
    await setNumber(user, days, '90');
    expect(pre(/tuf-kms rotate role/)).toBe(
      'tuf-kms rotate role snapshot \\\n  --keys 3 \\\n  --threshold 3 \\\n  --root-expires 90',
    );
    await setNumber(user, count, '2');
    await waitFor(() => expect(pre(/tuf-kms rotate role/)).toContain('--threshold 2'));
  });

  it('submits the root that authorises the new role keys', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ data: { task_id: 'role-1' } })));
    const { user, onSaveToHistory } = await open();
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), '{"signed":{"version":6}}');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('Metadata submitted successfully!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata').json).toEqual({ metadata: { root: { signed: { version: 6 } } } });
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ taskId: 'role-1' }));
  });

  it('treats "new root not signed by trusted root" as threshold progress', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ error: 'new root not signed by trusted root' }, { status: 400 })));
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"a","sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('Threshold not met')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign').json).toEqual({ role: 'root', signature: { keyid: 'a', sig: 's' } });
  });
});

describe('RotateDelegatedKeys', () => {
  const open = async () => {
    const p = props();
    const utils = renderWithProviders(<RotateDelegatedKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Delegated Role Keys' }));
    return { ...utils, ...p };
  };

  it('defaults the role name and builds the command', async () => {
    const { user } = await open();
    expect(pre(/tuf-kms rotate delegated/)).toBe('tuf-kms rotate delegated default \\\n  --keys 1 \\\n  --threshold 1');
    await user.clear(screen.getByPlaceholderText('default'));
    expect(pre(/tuf-kms rotate delegated/)).toContain('rotate delegated default');
    await user.type(screen.getByPlaceholderText('default'), '  beta-role ');
    const [count] = screen.getAllByRole('spinbutton');
    await setNumber(user, count, '2');
    expect(pre(/tuf-kms rotate delegated/)).toBe('tuf-kms rotate delegated beta-role \\\n  --keys 2 \\\n  --threshold 1');
  });

  it('loads delegated metadata for the trimmed role name', async () => {
    server.use(
      route('get', '/tuf/v1/metadata/delegated', () =>
        HttpResponse.json({ data: { trusted_delegated: { signed: { version: 2, expires: '2027-01-01T00:00:00Z' } } } }),
      ),
    );
    const { user } = await open();
    await user.clear(screen.getByPlaceholderText('default'));
    await user.type(screen.getByPlaceholderText('default'), ' qa ');
    await user.click(screen.getByRole('button', { name: /Get current delegated/ }));
    expect(await screen.findByText('Delegated metadata loaded successfully!')).toBeInTheDocument();
    expect(Object.fromEntries(lastCall('GET', '/tuf/v1/metadata/delegated').query)).toEqual({ appName: 'beta', roleName: 'qa' });
  });

  it('stages a rotation request as-is', async () => {
    server.use(route('post', '/tuf/v1/metadata/delegated/rotate', () => HttpResponse.json({ data: { task_id: 'del-rot-1' } })));
    const { user, onSaveToHistory } = await open();
    const request = { role: 'default', keys: [{ keyid: 'n1' }], threshold: 1 };
    await paste(user, screen.getByPlaceholderText(/delegated-rotation-request.json/), JSON.stringify(request));
    await user.click(screen.getByRole('button', { name: /Stage Delegated Rotation/ }));
    expect(await screen.findByText('Delegated rotation staged successfully!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/delegated/rotate').json).toEqual(request);
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'metadata-update', taskId: 'del-rot-1' }));
  });

  it('forwards the sign payload untouched and reports progress', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ error: 'threshold not reached: 1/2' }, { status: 400 })));
    const { user } = await open();
    const payload = { role: 'targets', signature: { keyid: 't1', sig: 'x' } };
    await paste(user, screen.getByPlaceholderText(/Paste sign payload JSON/), JSON.stringify(payload));
    await user.click(screen.getByRole('button', { name: /Submit Sign Payload/ }));
    expect(await screen.findByText('Threshold not met yet. Continue submitting required signatures.')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign').json).toEqual(payload);
  });

  it('reports completed signing', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ message: 'Signing complete' })));
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste sign payload JSON/), '{}');
    await user.click(screen.getByRole('button', { name: /Submit Sign Payload/ }));
    expect((await screen.findAllByText('Signing complete')).length).toBeGreaterThan(0);
  });

  it('rejects invalid request JSON', async () => {
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/delegated-rotation-request.json/), '{nope');
    await user.click(screen.getByRole('button', { name: /Stage Delegated Rotation/ }));
    expect(screen.getByText('Invalid JSON format')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata/delegated/rotate')).toHaveLength(0);
  });
});

describe('RotateRootKeys status and cleanup', () => {
  const open = async () => {
    const p = props();
    const utils = renderWithProviders(<RotateRootKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Root Keys' }));
    return { ...utils, ...p };
  };
  const submitSignature = async (user: UserEvent) => {
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"a","sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
  };

  it('auto-loads the trusted root and copies it', async () => {
    server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json({ data: { trusted_root: JSON.stringify({ data: { trusted_root: root } }) } })));
    const { user } = await open();
    const [expand] = await screen.findAllByRole('button', { name: /Current Root Metadata \(click to expand\)/ });
    expect(Object.fromEntries(lastCall('GET', '/tuf/v1/metadata/root').query)).toEqual({ appName: 'beta' });
    await user.click(expand);
    expect(screen.getByText(/"version": 5/, { selector: 'pre' })).toBeInTheDocument();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getAllByRole('button', { name: /Copy Root Metadata/ })[0]);
    expect(writeText).toHaveBeenCalledWith(JSON.stringify(root, null, 2));
    expect(await screen.findByText('Root metadata copied to clipboard successfully!')).toBeInTheDocument();
  });

  it('copies the rotate command', async () => {
    const { user } = await open();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: /Copy Command/ }));
    expect(writeText).toHaveBeenCalledWith('tuf-kms rotate root \\\n  --keys 2 \\\n  --root-expires 364');
  });

  it('keeps a failed auto-load silent but reports a manual one', async () => {
    server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json({ message: 'root unavailable' }, { status: 500 })));
    const { user } = await open();
    await waitFor(() => expect(callsTo('GET', '/tuf/v1/metadata/root').length).toBeGreaterThan(0));
    expect(screen.queryByText('root unavailable')).not.toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: /Get current root/ })[0]);
    expect(await screen.findByText('root unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Current Root Metadata/ })).not.toBeInTheDocument();
  });

  it('rejects a root response without trusted_root', async () => {
    server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json({ data: {} })));
    const { user } = await open();
    await user.click(screen.getAllByRole('button', { name: /Get current root/ })[0]);
    expect(await screen.findByText('Invalid response: missing trusted_root field')).toBeInTheDocument();
  });

  it('records a failed metadata submit in history', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ message: 'version must increase' }, { status: 400 })));
    const { user, onSaveToHistory, onCheckTufTasks } = await open();
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), '{"signed":{}}');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('version must increase')).toBeInTheDocument();
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'root-meta-update', status: 'failed' }));
    vi.advanceTimersByTime(1500);
    expect(onCheckTufTasks).not.toHaveBeenCalled();
  });

  it('checks the new task one second after submitting metadata', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ data: { task_id: 'rot-2' } })));
    const { user, onCheckTufTasks } = await open();
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), '{}');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    await screen.findByText('Metadata submitted successfully!');
    expect(onCheckTufTasks).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(onCheckTufTasks).toHaveBeenCalledWith('rot-2');
  });

  it('requires a payload and valid JSON before submitting metadata', async () => {
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), '{bad');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(screen.getByText('Invalid JSON format')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata')).toHaveLength(0);
  });

  it.each([
    [{ message: 'Metadata update finished' }, 'Metadata update finished!', 'Metadata update finished! Root keys rotation completed successfully.'],
    [{ data: { message: '2 of 3 signed' } }, 'Signature submitted', 'Signature submitted: 2 of 3 signed'],
    [{}, 'Signature submitted', 'Signature submitted successfully! Continue submitting more signatures until threshold is reached.'],
  ])('shows sign response %j', async (body, banner, toast) => {
    signResponse(body);
    const { user } = await open();
    await submitSignature(user);
    expect(await screen.findByText(toast)).toBeInTheDocument();
    expect(screen.getByText(banner, { selector: 'p' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste signature JSON here/)).toHaveValue('');
  });

  it('falls back to got/want progress when the detailed format is missing', async () => {
    signResponse({ error: 'threshold not reached: got 1, want 2' }, 400);
    const { user } = await open();
    await submitSignature(user);
    expect(await screen.findByText('Threshold not reached yet', { selector: 'p' })).toBeInTheDocument();
    expect(paragraph('Progress: 1 of 2 signatures submitted (1 more signature needed)')).toBeInTheDocument();
  });

  it('keeps the payload and asks to retry on a real signing error', async () => {
    signResponse({ error: 'signature does not verify' }, 400);
    const { user } = await open();
    await submitSignature(user);
    expect(await screen.findByText('Error submitting signature')).toBeInTheDocument();
    expect(screen.getAllByText('signature does not verify').length).toBeGreaterThan(0);
    expect(screen.getByText('Please check the error message above and try again.')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste signature JSON here/)).toHaveValue('{"keyid":"a","sig":"s"}');
  });

  it('parses progress from the message field as well', async () => {
    signResponse(
      { message: 'rejected. Progress: 2/3 signatures collected (1 old + 1 new). 1 more required (0 old + 1 new).' },
      409,
    );
    const { user } = await open();
    await submitSignature(user);
    expect(await screen.findByText('2 / 3')).toBeInTheDocument();
    expect(screen.getByText('1 more signature required')).toBeInTheDocument();
  });

  it.each([
    [{ message: 'No metadata pending signing available' }, 200, 'Metadata update finished!'],
    [{ message: 'waiting for signatures' }, 200, 'Metadata update in progress'],
    [{}, 200, 'Status unknown'],
    [{ message: 'not enough signatures' }, 400, 'Threshold not reached'],
    [{ error: 'redis down' }, 500, 'Error checking status'],
  ])('checks signing status %j (%i)', async (body, status, banner) => {
    signStatus(body, status);
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Check Status/ }));
    expect(await screen.findByText(banner, { selector: 'p' })).toBeInTheDocument();
    expect(Object.fromEntries(lastCall('GET', '/tuf/v1/metadata/sign').query)).toEqual({ appName: 'beta' });
  });

  it('deletes signing metadata, records the task and resets signature state', async () => {
    signResponse({ error: 'not enough signatures' }, 400);
    deleteResponse({ message: 'Metadata sign delete accepted.', data: { task_id: 'del-1', last_update: '2026-11-16T10:00:00Z' } });
    const { user, onSaveToHistory, onCheckTufTasks } = await open();
    await submitSignature(user);
    await screen.findByText('Threshold not reached yet', { selector: 'p' });
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('Metadata sign delete accepted.')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign/delete').json).toEqual({ role: 'root' });
    expect(onSaveToHistory).toHaveBeenCalledWith({
      timestamp: '2026-11-16T10:00:00Z',
      appName: 'beta',
      operation: 'metadata-update',
      status: 'pending',
      taskId: 'del-1',
    });
    expect(screen.queryByText('Threshold not reached yet', { selector: 'p' })).not.toBeInTheDocument();
    vi.advanceTimersByTime(1000);
    expect(onCheckTufTasks).toHaveBeenCalledWith('del-1');
  });

  it('treats "nothing to delete" as success without a history entry', async () => {
    deleteResponse({ message: 'no signing in progress' }, 404);
    const { user, onSaveToHistory } = await open();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('no signing in progress')).toBeInTheDocument();
    expect(onSaveToHistory).not.toHaveBeenCalled();
  });

  it('reports a failed delete', async () => {
    deleteResponse({ message: 'lock held' }, 500);
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('lock held')).toBeInTheDocument();
  });

  it('renders nothing without an app or before bootstrap', () => {
    const { container } = renderWithProviders(<RotateRootKeys {...props()} isBootstrapSuccess={false} />);
    expect(container.querySelector('h2')).toBeNull();
  });
});

describe('RotateRoleKeys status and cleanup', () => {
  const open = async () => {
    const p = { ...props(), onUpdateMetadata: vi.fn() };
    const utils = renderWithProviders(<RotateRoleKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Top-Level Role Keys' }));
    return { ...utils, ...p };
  };
  const submitSignature = async (user: UserEvent) => {
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"a","sig":"s"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
  };

  it('omits --root-expires when days is zero and copies the command', async () => {
    const { user } = await open();
    const [, , days] = screen.getAllByRole('spinbutton');
    await setNumber(user, days, '0');
    expect(pre(/tuf-kms rotate role/)).toBe('tuf-kms rotate role timestamp \\\n  --keys 1 \\\n  --threshold 1');
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: /Copy Command/ }));
    expect(writeText).toHaveBeenCalledWith('tuf-kms rotate role timestamp \\\n  --keys 1 \\\n  --threshold 1');
  });

  it('auto-loads, shows and copies the trusted root', async () => {
    const { user } = await open();
    const [expand] = await screen.findAllByRole('button', { name: /Current Root Metadata \(click to expand\)/ });
    await user.click(expand);
    expect(screen.getByText(/"threshold": 1/, { selector: 'pre' })).toBeInTheDocument();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getAllByRole('button', { name: /Copy Root Metadata/ })[0]);
    expect(writeText).toHaveBeenCalledWith(JSON.stringify(root, null, 2));
  });

  it('reports a manual root fetch failure', async () => {
    server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json({ data: { trusted_root: 'not json' } })));
    const { user } = await open();
    await user.click(screen.getAllByRole('button', { name: /Get current root/ })[0]);
    expect(await screen.findByText('Invalid trusted_root format')).toBeInTheDocument();
  });

  it('records a failed metadata submit in history', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ data: {} })));
    const { user, onSaveToHistory } = await open();
    await paste(user, screen.getByPlaceholderText(/root-metadata.json/), '{}');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('Invalid response: missing task_id')).toBeInTheDocument();
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }));
  });

  it.each([
    [{ message: 'Metadata update finished' }, 200, 'Metadata update finished successfully.'],
    [{ message: 'accepted' }, 200, 'Signature added successfully.'],
    [{ error: 'No metadata pending signing available' }, 404, 'Metadata update finished successfully.'],
    [{ error: 'bad key' }, 400, 'Error submitting signature'],
  ])('shows sign response %j (%i)', async (body, status, banner) => {
    signResponse(body, status);
    const { user } = await open();
    await submitSignature(user);
    expect(await screen.findByText(banner, { selector: 'p' })).toBeInTheDocument();
  });

  it('validates the signature payload before sending', async () => {
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), '{"keyid":"a"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(screen.getByText('Signature must contain keyid and sig fields')).toBeInTheDocument();
    await paste(user, screen.getByPlaceholderText(/Paste signature JSON here/), 'nope');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(screen.getByText('Invalid JSON format')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata/sign')).toHaveLength(0);
  });

  it.each([
    [{ message: 'Metadata update finished' }, 200, 'Metadata update finished.'],
    [{ message: 'pending' }, 200, 'Metadata update in progress.'],
    [{ error: 'threshold not reached' }, 400, 'Threshold not reached yet.'],
    [{ message: 'boom' }, 500, 'Error checking status.'],
  ])('checks signing status %j (%i)', async (body, status, banner) => {
    signStatus(body, status);
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Check Status/ }));
    expect(await screen.findByText(banner, { selector: 'p' })).toBeInTheDocument();
  });

  it('deletes root signing metadata and schedules a task check', async () => {
    deleteResponse({ message: 'accepted', data: { task_id: 'del-2' } });
    const { user, onSaveToHistory, onCheckTufTasks } = await open();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('accepted')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign/delete').json).toEqual({ role: 'root' });
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ taskId: 'del-2', status: 'pending' }));
    vi.advanceTimersByTime(1000);
    expect(onCheckTufTasks).toHaveBeenCalledWith('del-2');
  });

  it('reports a failed delete', async () => {
    deleteResponse({ error: 'lock held' }, 500);
    const { user, onSaveToHistory } = await open();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('lock held')).toBeInTheDocument();
    expect(onSaveToHistory).not.toHaveBeenCalled();
  });
});

describe('RotateDelegatedKeys metadata and cleanup', () => {
  const open = async () => {
    const p = props();
    const utils = renderWithProviders(<RotateDelegatedKeys {...p} />);
    await utils.user.click(screen.getByRole('heading', { name: 'Rotate Delegated Role Keys' }));
    return { ...utils, ...p };
  };
  const targets = { signed: { version: 7, expires: '2027-02-01T00:00:00Z' } };

  it('loads, shows and copies targets metadata', async () => {
    server.use(route('get', '/tuf/v1/metadata/targets', () => HttpResponse.json({ data: { trusted_targets: targets } })));
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Get current targets/ }));
    expect(await screen.findByText('Targets metadata loaded successfully!')).toBeInTheDocument();
    expect(Object.fromEntries(lastCall('GET', '/tuf/v1/metadata/targets').query)).toEqual({ appName: 'beta' });
    await user.click(screen.getByRole('button', { name: /Current Targets Metadata \(click to expand\)/ }));
    expect(screen.getByText(/"version": 7/, { selector: 'pre' })).toBeInTheDocument();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: /Copy Targets Metadata/ }));
    expect(writeText).toHaveBeenCalledWith(JSON.stringify(targets, null, 2));
  });

  it('shows and copies delegated metadata from a string payload', async () => {
    const delegated = { signed: { version: 3, expires: '2027-03-01T00:00:00Z' } };
    server.use(route('get', '/tuf/v1/metadata/delegated', () => HttpResponse.json({ trusted_delegated: JSON.stringify(delegated) })));
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Get current delegated/ }));
    await user.click(await screen.findByRole('button', { name: /Current Delegated Metadata \(click to expand\)/ }));
    expect(screen.getByText(/"version": 3/, { selector: 'pre' })).toBeInTheDocument();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: /Copy Delegated Metadata/ }));
    expect(writeText).toHaveBeenCalledWith(JSON.stringify(delegated, null, 2));
  });

  it.each([
    ['targets', /Get current targets/, '/tuf/v1/metadata/targets', 'Invalid response: missing trusted_targets'],
    ['delegated', /Get current delegated/, '/tuf/v1/metadata/delegated', 'Invalid response: missing trusted_delegated'],
  ])('rejects %s metadata without a signed envelope', async (_, button, path, message) => {
    server.use(route('get', path, () => HttpResponse.json({ data: { something: 'else' } })));
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: button }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it('shows the server message when a metadata fetch fails', async () => {
    server.use(route('get', '/tuf/v1/metadata/targets', () => HttpResponse.json({ message: 'no targets yet' }, { status: 404 })));
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Get current targets/ }));
    expect(await screen.findByText('no targets yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Current Targets Metadata/ })).not.toBeInTheDocument();
  });

  it('records a failed staging in history', async () => {
    server.use(route('post', '/tuf/v1/metadata/delegated/rotate', () => HttpResponse.json({ message: 'unknown role' }, { status: 400 })));
    const { user, onSaveToHistory } = await open();
    await paste(user, screen.getByPlaceholderText(/delegated-rotation-request.json/), '{}');
    await user.click(screen.getByRole('button', { name: /Stage Delegated Rotation/ }));
    expect(await screen.findByText('unknown role')).toBeInTheDocument();
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'metadata-update', status: 'failed' }));
  });

  it.each([
    [{ message: 'Signature accepted, 1 more' }, 200, 'Signature accepted, 1 more'],
    [{}, 200, 'Signature payload submitted successfully.'],
    [{ error: 'role unknown' }, 400, 'Error submitting signature payload.'],
  ])('shows sign payload response %j (%i)', async (body, status, banner) => {
    signResponse(body, status);
    const { user } = await open();
    await paste(user, screen.getByPlaceholderText(/Paste sign payload JSON/), '{}');
    await user.click(screen.getByRole('button', { name: /Submit Sign Payload/ }));
    expect((await screen.findAllByText(banner, { selector: 'p' })).length).toBeGreaterThan(0);
  });

  it.each([
    [{ message: 'nothing pending' }, 200, 'nothing pending'],
    [{}, 200, 'Signing queue checked successfully'],
    [{ error: 'redis down' }, 500, 'redis down'],
  ])('shows the signing queue %j (%i)', async (body, status, text) => {
    signStatus(body, status);
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Check Status/ }));
    expect(await screen.findByText(text, { selector: 'p' })).toBeInTheDocument();
  });

  it('deletes signing metadata for targets and the delegated role', async () => {
    let n = 0;
    server.use(route('post', '/tuf/v1/metadata/sign/delete', () => HttpResponse.json(++n === 1 ? { message: 'targets cleared', data: { task_id: 't-1' } } : { message: 'role cleared' })));
    const { user, onSaveToHistory, onCheckTufTasks } = await open();
    await user.clear(screen.getByPlaceholderText('default'));
    await user.type(screen.getByPlaceholderText('default'), 'qa');
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('targets: targets cleared | qa: role cleared')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata/sign/delete').map((c) => c.json)).toEqual([{ role: 'targets' }, { role: 'qa' }]);
    expect(onSaveToHistory).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1000);
    expect(onCheckTufTasks).toHaveBeenCalledWith('t-1');
  });

  it('deletes targets once when the delegated role is named targets', async () => {
    deleteResponse({ message: 'ok' });
    const { user } = await open();
    await user.clear(screen.getByPlaceholderText('default'));
    await user.type(screen.getByPlaceholderText('default'), 'targets');
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('targets: ok')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata/sign/delete')).toHaveLength(1);
  });

  it('stops at the first failed delete', async () => {
    deleteResponse({ message: 'lock held' }, 500);
    const { user } = await open();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('lock held')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata/sign/delete')).toHaveLength(1);
  });
});
