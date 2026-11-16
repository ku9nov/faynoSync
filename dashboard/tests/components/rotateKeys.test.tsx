import { beforeEach, describe, expect, it, vi } from 'vitest';
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

beforeEach(() => {
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
