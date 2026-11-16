import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, db, lastCall, route, useFakeApi, version } from '../fakeApi';
import { file, pick } from '../helpers';
import { UploadModal } from '@/components/modals/UploadModal';
import { HomePage } from '@/pages/HomePage';

beforeEach(() => {
  useFakeApi();
  db.platforms.push({
    ID: 'pl-3',
    PlatformName: 'macos',
    Updated_at: '',
    Updaters: [
      { type: 'manual', default: true },
      { type: 'tauri', default: false },
    ],
  });
});

const fileInput = () => document.querySelector('input[type="file"]') as HTMLInputElement;

describe('UploadModal', () => {
  const renderUpload = () => {
    const onClose = vi.fn();
    const utils = renderWithProviders(<UploadModal onClose={onClose} />);
    return { ...utils, onClose };
  };

  it('uploads files with the picked metadata', async () => {
    server.use(route('post', '/upload', () => HttpResponse.json({ uploadResult: { Uploaded: 'ok' } })));
    const { user, onClose } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await user.type(screen.getByPlaceholderText('e.g., 0.0.1.0'), '2.0.0');
    await pick(user, 'Channel', 'nightly');
    await pick(user, 'Platform', 'windows');
    expect(screen.getByRole('combobox', { name: 'Updater' })).toHaveTextContent('manual');
    await pick(user, 'Updater', 'squirrel_windows');
    await pick(user, 'Architecture', 'amd64');
    await user.click(screen.getByRole('checkbox', { name: 'Publish' }));
    await user.click(screen.getByRole('checkbox', { name: 'Intermediate' }));
    await user.type(screen.getByPlaceholderText(/Changes in this version/), '- fixed');
    await user.upload(fileInput(), [file('Setup.exe'), file('RELEASES')]);
    expect(screen.getByText('Setup.exe')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(await screen.findByText('Files uploaded successfully!')).toBeInTheDocument();
    const call = lastCall('POST', '/upload');
    expect(call.form?.data).toEqual({
      app_name: 'alpha',
      version: '2.0.0',
      channel: 'nightly',
      publish: true,
      critical: false,
      intermediate: true,
      platform: 'windows',
      arch: 'amd64',
      changelog: '- fixed',
      updater: 'squirrel_windows',
    });
    expect(call.files).toEqual(['file:Setup.exe', 'file:RELEASES']);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it('omits the manual updater and sends the tauri signature', async () => {
    server.use(route('post', '/upload', () => HttpResponse.json({})));
    const { user } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await user.type(screen.getByPlaceholderText('e.g., 0.0.1.0'), '1.0.0');
    await pick(user, 'Platform', 'macos');
    await pick(user, 'Updater', 'tauri');
    await user.type(screen.getByPlaceholderText('Enter signature for Tauri updater'), 'sig==');
    await user.upload(fileInput(), file('app.tar.gz'));
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(lastCall('POST', '/upload')).toBeDefined());
    expect(lastCall('POST', '/upload').form?.data).toMatchObject({ updater: 'tauri', signature: 'sig==' });

    await pick(user, 'Updater', 'manual');
    expect(screen.queryByPlaceholderText('Enter signature for Tauri updater')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(callsTo('POST', '/upload')).toHaveLength(2));
    const data = lastCall('POST', '/upload').form?.data as Record<string, unknown>;
    expect(data.updater).toBeUndefined();
    expect(data.signature).toBeUndefined();
  });

  it('switching platform resets the updater', async () => {
    const { user } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await pick(user, 'Platform', 'macos');
    await pick(user, 'Updater', 'tauri');
    expect(screen.getByPlaceholderText('Enter signature for Tauri updater')).toBeInTheDocument();
    await pick(user, 'Platform', 'linux');
    expect(screen.queryByRole('combobox', { name: 'Updater' })).toBeNull();
    expect(screen.queryByPlaceholderText('Enter signature for Tauri updater')).toBeNull();
  });

  it('does not submit without files', async () => {
    const { user } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await user.type(screen.getByPlaceholderText('e.g., 0.0.1.0'), '1.0.0');
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(callsTo('POST', '/upload')).toHaveLength(0);
  });

  it('shows the server error', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    server.use(route('post', '/upload', () => HttpResponse.json({ error: 'version already exists' }, { status: 409 })));
    const { user, onClose } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await user.type(screen.getByPlaceholderText('e.g., 0.0.1.0'), '1.0.0');
    await user.upload(fileInput(), file('a.bin'));
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText('Upload failed')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show details' }));
    expect(screen.getByText('version already exists')).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('asks to create an app first', async () => {
    db.apps = [];
    renderUpload();
    expect(await screen.findByText(/You don't have created applications/)).toBeInTheDocument();
  });

  it('removes a picked file', async () => {
    const { user } = renderUpload();
    await pick(user, 'App name', 'alpha');
    await user.upload(fileInput(), [file('a.bin'), file('b.bin')]);
    await user.click(screen.getAllByRole('button', { name: 'Remove file' })[0]);
    expect(screen.queryByText('a.bin')).toBeNull();
    expect(screen.getByText('b.bin')).toBeInTheDocument();
  });
});

describe('EditVersionModal', () => {
  const openEditor = async (overrides: Record<string, unknown> = {}) => {
    db.versions = [version('1', overrides)];
    const utils = renderWithProviders(<HomePage />, { route: '/applications/alpha', path: '/applications/:appName' });
    await screen.findByTitle('Version 1.0.1');
    const card = screen.getByTitle('Version 1.0.1').closest('.sharedCard') as HTMLElement;
    await utils.user.click(within(card).getByRole('button', { name: 'Edit' }));
    const modal = screen.getByRole('heading', { name: 'Edit version 1.0.1' });
    expect(modal).toBeInTheDocument();
    return utils;
  };

  const updateHandler = () =>
    route('post', '/apps/update', () => HttpResponse.json({ updatedResult: { Updated: true } }));

  it('saves flags, changelog and rollout', async () => {
    server.use(updateHandler());
    const { user } = await openEditor({ RolloutPercent: 50 });
    expect(screen.getByRole('checkbox', { name: 'Published' })).toBeChecked();
    expect(screen.getByLabelText('Rollout percent')).toHaveValue(50);
    expect(screen.getByText('Ramping')).toBeInTheDocument();

    await user.click(screen.getByRole('checkbox', { name: 'Published' }));
    await user.click(screen.getByRole('checkbox', { name: 'Critical' }));
    const changelog = screen.getByPlaceholderText('Enter changelog in Markdown format...');
    await user.clear(changelog);
    await user.type(changelog, '**new**');
    await user.click(screen.getByRole('button', { name: 'Increase by 5' }));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(lastCall('POST', '/apps/update')).toBeDefined());
    const call = lastCall('POST', '/apps/update');
    expect(call.form?.data).toEqual({
      id: '1',
      app_name: 'alpha',
      version: '1.0.1',
      channel: 'stable',
      publish: false,
      critical: true,
      intermediate: false,
      changelog: '**new**',
      rollout: 55,
    });
    expect(call.files).toEqual([]);
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Edit version 1.0.1' })).toBeNull());
  });

  it.each([
    ['0', 'Paused', 'Paused — no new device is offered this version.'],
    ['5', 'Canary', 'Offered to 5 of every 100 devices on stable.'],
    ['100', 'Full rollout', 'Every device on stable is offered this version.'],
    ['250', 'Full rollout', 'Every device on stable is offered this version.'],
  ])('rollout %s%% reads as %s', async (value, zone, hint) => {
    const { user } = await openEditor();
    const input = screen.getByLabelText('Rollout percent');
    await user.clear(input);
    await user.type(input, value);
    expect(screen.getByText(zone)).toBeInTheDocument();
    expect(screen.getByText(hint)).toBeInTheDocument();
  });

  it('does not go below 0 or above 100 with the buttons', async () => {
    const { user } = await openEditor({ RolloutPercent: 2 });
    await user.click(screen.getByRole('button', { name: 'Decrease by 5' }));
    expect(screen.getByLabelText('Rollout percent')).toHaveValue(0);
    await user.clear(screen.getByLabelText('Rollout percent'));
    await user.type(screen.getByLabelText('Rollout percent'), '98');
    await user.click(screen.getByRole('button', { name: 'Increase by 5' }));
    expect(screen.getByLabelText('Rollout percent')).toHaveValue(100);
  });

  it('adds files only once platform and arch are picked', async () => {
    server.use(updateHandler());
    const { user } = await openEditor();
    await user.upload(fileInput(), file('extra.rpm'));
    const save = screen.getByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();
    await pick(user, 'Platform', 'windows');
    expect(save).toBeDisabled();
    await pick(user, 'Architecture', 'arm64');
    expect(save).toBeEnabled();
    await pick(user, 'Updater', 'squirrel_windows');
    await user.click(save);
    await waitFor(() => expect(lastCall('POST', '/apps/update')).toBeDefined());
    const call = lastCall('POST', '/apps/update');
    expect(call.form?.data).toMatchObject({ platform: 'windows', arch: 'arm64', updater: 'squirrel_windows' });
    expect(call.files).toEqual(['file:extra.rpm']);
  });

  it('shows the save error and stays open', async () => {
    server.use(route('post', '/apps/update', () => HttpResponse.json({ error: 'locked' }, { status: 400 })));
    const { user } = await openEditor();
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('locked')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Edit version 1.0.1' })).toBeInTheDocument();
  });

  it('deletes an artifact after typing platform/arch', async () => {
    server.use(route('post', '/artifact/delete', () => HttpResponse.json({})));
    const { user } = await openEditor({
      Artifacts: [
        { ID: 'a', link: 'l1', platform: 'linux', arch: 'amd64', package: '.deb' },
        { ID: 'b', link: 'l2', platform: 'windows', arch: 'arm64', package: '.exe' },
      ],
    });
    const editor = screen.getByRole('heading', { name: 'Edit version 1.0.1' }).parentElement!.parentElement as HTMLElement;
    await user.click(within(editor).getAllByRole('button', { name: 'Delete' })[1]);
    expect(screen.getByText('To delete artifact please enter this windows/arm64:')).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('Enter platform/arch'), 'windows/arm64');
    const confirmForm = screen.getByPlaceholderText('Enter platform/arch').closest('form') as HTMLElement;
    await user.click(within(confirmForm).getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('Artifact deleted')).toBeInTheDocument();
    expect(lastCall('POST', '/artifact/delete').form?.data).toEqual({
      id: '1',
      app_name: 'alpha',
      version: '1.0.1',
      artifacts_to_delete: ['1'],
    });
  });

  it('unsigns a TUF artifact and records it', async () => {
    db.apps = db.apps.map((a) => (a.AppName === 'alpha' ? { ...a, Tuf: true } : a));
    server.use(route('post', '/tuf/v1/artifacts/delete', () => HttpResponse.json({ data: { task_id: 'unsign-1' } })));
    const { user } = await openEditor({
      Artifacts: [{ ID: 'a', link: 'l1', platform: 'linux', arch: 'amd64', package: '.deb', TufTaskID: 't', TufSigned: true }],
    });
    await user.click(await screen.findByRole('button', { name: 'Unsign artifact from TUF' }));
    await waitFor(() => expect(lastCall('POST', '/tuf/v1/artifacts/delete')).toBeDefined());
    expect(lastCall('POST', '/tuf/v1/artifacts/delete').json).toEqual({
      id: '1',
      app_name: 'alpha',
      version: '1.0.1',
      artifacts_to_delete: ['0'],
    });
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({
      operation: 'unsign',
      taskId: 'unsign-1',
      version: '1.0.1',
    });
    expect((await screen.findAllByTitle('Publish TUF artifacts')).length).toBeGreaterThan(0);
  });

  it('records failed TUF publishes in history', async () => {
    db.apps = db.apps.map((a) => (a.AppName === 'alpha' ? { ...a, Tuf: true } : a));
    server.use(route('post', '/tuf/v1/artifacts/publish', () => HttpResponse.json({ message: 'signer offline' }, { status: 503 })));
    const { user } = await openEditor({
      Artifacts: [{ ID: 'a', link: 'l1', platform: 'linux', arch: 'amd64', package: '.deb', TufTaskID: null, TufSigned: false }],
    });
    const publishButtons = await screen.findAllByTitle('Publish TUF artifacts');
    await user.click(publishButtons[publishButtons.length - 1]);
    expect(await screen.findByText('signer offline')).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('tuf-history')!)[0]).toMatchObject({ operation: 'publish', status: 'failed' });
  });
});
