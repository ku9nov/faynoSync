import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, lastCall, route, useFakeApi } from '../fakeApi';
import { RenewRoot } from '@/components/settings/tuf/RenewRoot';

const root = {
  signed: {
    _type: 'root',
    version: 3,
    expires: '2027-01-01T00:00:00Z',
    keys: { k1: {}, k2: {}, k3: {} },
    roles: { root: { keyids: ['k1', 'k2', 'k3'], threshold: 2 } },
  },
  signatures: [],
};

let rootResponse: unknown;

beforeEach(() => {
  useFakeApi();
  vi.spyOn(console, 'error').mockImplementation(() => {});
  rootResponse = { data: { trusted_root: root } };
  server.use(route('get', '/tuf/v1/metadata/root', () => HttpResponse.json(rootResponse as Record<string, unknown>)));
});

const renderRenew = async () => {
  const onSaveToHistory = vi.fn();
  const onCheckTufTasks = vi.fn();
  const utils = renderWithProviders(
    <RenewRoot selectedApp="beta" isBootstrapSuccess onSaveToHistory={onSaveToHistory} onCheckTufTasks={onCheckTufTasks} />,
  );
  await utils.user.click(screen.getByRole('heading', { name: 'Renew Root' }));
  return { ...utils, onSaveToHistory, onCheckTufTasks };
};

const signatureBox = () => screen.getByPlaceholderText(/Paste signature JSON here/);
const typeJson = async (user: Awaited<ReturnType<typeof renderRenew>>['user'], el: HTMLElement, text: string) => {
  await user.clear(el);
  await user.click(el);
  await user.paste(text);
};

describe('RenewRoot', () => {
  it('renders nothing before bootstrap', () => {
    renderWithProviders(<RenewRoot selectedApp="beta" isBootstrapSuccess={false} onSaveToHistory={vi.fn()} onCheckTufTasks={vi.fn()} />);
    expect(screen.queryByRole('heading', { name: 'Renew Root' })).toBeNull();
  });

  it('loads the trusted root and explains the next version', async () => {
    await renderRenew();
    expect(await screen.findByText('version 3')).toBeInTheDocument();
    expect(screen.getByText('2027-01-01T00:00:00Z')).toBeInTheDocument();
    expect(screen.getByText('The renewal publishes version 4 with the same keys.')).toBeInTheDocument();
    expect(lastCall('GET', '/tuf/v1/metadata/root').query.get('appName')).toBe('beta');
  });

  it.each([
    ['a JSON string', JSON.stringify(root)],
    ['a nested envelope', { data: { trusted_root: root } }],
  ])('accepts the trusted root as %s', async (_, trusted) => {
    rootResponse = { data: { trusted_root: trusted } };
    await renderRenew();
    expect(await screen.findByText('version 3')).toBeInTheDocument();
  });

  it('rejects a root without keys and roles', async () => {
    rootResponse = { data: { trusted_root: { signed: { version: 9 } } } };
    const { user } = await renderRenew();
    await waitFor(() => expect(callsTo('GET', '/tuf/v1/metadata/root').length).toBeGreaterThan(0));
    expect(screen.queryByText('version 9')).toBeNull();
    await user.click(screen.getAllByRole('button', { name: /Get current root/ })[0]);
    expect(await screen.findByText('Invalid trusted_root format')).toBeInTheDocument();
  });

  it('puts the expiration into the renew command', async () => {
    const { user } = await renderRenew();
    const days = screen.getByRole('spinbutton');
    const command = () => screen.getByText(/tuf-kms renew root/, { selector: 'pre' }).textContent;
    expect(days).toHaveValue(364);
    expect(command()).toContain('--expires 364');
    await user.tripleClick(days);
    await user.keyboard('90');
    expect(command()).toContain('--expires 90');
    await user.tripleClick(days);
    await user.keyboard('999');
    expect(command()).toContain('--expires 365');
  });

  it('validates and submits the renewed root metadata', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ data: { task_id: 'renew-1', last_update: '2026-01-01T00:00:00Z' } })));
    const { user, onSaveToHistory, onCheckTufTasks } = await renderRenew();
    const box = screen.getByPlaceholderText(/Paste the contents of out\/root-metadata.json here/);
    await typeJson(user, box, '{oops');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(screen.getByText('Invalid JSON format')).toBeInTheDocument();
    expect(callsTo('POST', '/tuf/v1/metadata')).toHaveLength(0);

    const renewed = { signed: { ...root.signed, version: 4 }, signatures: [] };
    await typeJson(user, box, JSON.stringify(renewed));
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('Metadata submitted successfully!')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata').json).toEqual({ metadata: { root: renewed } });
    expect(lastCall('POST', '/tuf/v1/metadata').query.get('appName')).toBe('beta');
    expect(onSaveToHistory).toHaveBeenCalledWith(
      expect.objectContaining({ operation: 'root-meta-update', status: 'pending', taskId: 'renew-1' }),
    );
    vi.advanceTimersByTime(1100);
    expect(onCheckTufTasks).toHaveBeenCalledWith('renew-1');
    vi.useRealTimers();
  });

  it('records a failed metadata submission', async () => {
    server.use(route('post', '/tuf/v1/metadata', () => HttpResponse.json({ message: 'version must increase' }, { status: 400 })));
    const { user, onSaveToHistory } = await renderRenew();
    await typeJson(user, screen.getByPlaceholderText(/root-metadata.json/), '{}');
    await user.click(screen.getByRole('button', { name: /Submit Metadata/ }));
    expect(await screen.findByText('version must increase')).toBeInTheDocument();
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'root-meta-update', status: 'failed' }));
  });

  it('requires keyid and sig in a signature', async () => {
    const { user } = await renderRenew();
    await typeJson(user, signatureBox(), '{"keyid":"k1"}');
    expect(screen.getByText('Signature must contain keyid and sig fields')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(callsTo('POST', '/tuf/v1/metadata/sign')).toHaveLength(0);
  });

  it('shows threshold progress against the root threshold, not the doubled server total', async () => {
    server.use(
      route('post', '/tuf/v1/metadata/sign', () =>
        HttpResponse.json(
          {
            error:
              'not enough signatures. Progress: 1/4 signatures collected. Old keys signed: [k1aaaaaaaaaa] Missing old keys: [k1aaaaaaaaaa k2bbbbbbbbbb k3cccccccccc]',
          },
          { status: 400 },
        ),
      ),
    );
    const { user } = await renderRenew();
    await screen.findByText('version 3');
    await typeJson(user, signatureBox(), '{"keyid":"k1aaaaaaaaaa","sig":"abc"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('Threshold not reached yet')).toBeInTheDocument();
    expect(screen.getByText('1 / 2')).toBeInTheDocument();
    expect(screen.getByText('1 more signature required to reach the root threshold')).toBeInTheDocument();
    expect(screen.getByText('k1aaaaaa...')).toBeInTheDocument();
    expect(screen.getByText('k2bbbbbb...')).toBeInTheDocument();
    expect(screen.getByText('k3cccccc...')).toBeInTheDocument();
    expect(screen.getAllByText('k1aaaaaa...')).toHaveLength(1);
    expect(lastCall('POST', '/tuf/v1/metadata/sign').json).toEqual({
      role: 'root',
      signature: { keyid: 'k1aaaaaaaaaa', sig: 'abc' },
    });
    expect(signatureBox()).toHaveValue('');
  });

  it('reports the renewed root as live when signing finishes', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ message: 'Metadata update finished' })));
    const { user } = await renderRenew();
    await typeJson(user, signatureBox(), '{"keyid":"k2","sig":"def"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('Metadata update finished! The renewed root is live.')).toBeInTheDocument();
  });

  it('keeps unknown signing errors visible', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign', () => HttpResponse.json({ error: 'signature does not verify' }, { status: 400 })));
    const { user } = await renderRenew();
    await typeJson(user, signatureBox(), '{"keyid":"k2","sig":"bad"}');
    await user.click(screen.getByRole('button', { name: /Submit Signature/ }));
    expect(await screen.findByText('Error submitting signature')).toBeInTheDocument();
    expect(signatureBox()).toHaveValue('{"keyid":"k2","sig":"bad"}');
  });

  it.each([
    [{ message: 'Metadata update finished' }, 200, 'Metadata update finished!'],
    [{ message: 'waiting for 1 more' }, 200, 'Metadata update in progress'],
    [{ error: 'threshold not reached' }, 400, 'Threshold not reached'],
  ])('checks signing status %j', async (body, status, text) => {
    server.use(route('get', '/tuf/v1/metadata/sign', () => HttpResponse.json(body, { status })));
    const { user } = await renderRenew();
    await user.click(screen.getByRole('button', { name: /Check Status/ }));
    expect((await screen.findAllByText(text)).length).toBeGreaterThan(0);
  });

  it('deletes pending root signing metadata', async () => {
    server.use(route('post', '/tuf/v1/metadata/sign/delete', () => HttpResponse.json({ message: 'deleted', data: { task_id: 'del-1' } })));
    const { user, onSaveToHistory } = await renderRenew();
    await user.click(screen.getByRole('button', { name: /Delete signing metadata/ }));
    expect(await screen.findByText('deleted')).toBeInTheDocument();
    expect(lastCall('POST', '/tuf/v1/metadata/sign/delete').json).toEqual({ role: 'root' });
    expect(onSaveToHistory).toHaveBeenCalledWith(expect.objectContaining({ operation: 'metadata-update', taskId: 'del-1' }));
  });
});
