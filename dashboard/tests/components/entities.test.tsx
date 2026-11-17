import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, db, lastCall, route, useFakeApi } from '../fakeApi';
import { ChannelsPage } from '@/pages/ChannelsPage';
import { ArchitecturesPage } from '@/pages/ArchitecturesPage';
import { PlatformsPage } from '@/pages/PlatformsPage';

beforeEach(() => useFakeApi());

const card = (name: string) => screen.getByRole('heading', { name }).closest('.sharedCard') as HTMLElement;

const simpleEntities = [
  {
    kind: 'channel',
    Page: ChannelsPage,
    api: 'channel',
    field: 'channel',
    existing: ['stable', 'nightly'],
    createButton: 'Create Channel',
    createTitle: 'Create Channel',
    createLabel: 'Channel Name',
    editTitle: 'Edit Channel',
    editLabel: 'Rename Channel',
    deleteTitle: 'Delete channel',
    deletePlaceholder: 'Enter channel name',
    empty: () => (db.channels = []),
    emptyText: 'No channels have been created yet.',
    notFound: 'No channels found matching your search.',
    firstId: 'ch-1',
  },
  {
    kind: 'architecture',
    Page: ArchitecturesPage,
    api: 'arch',
    field: 'arch',
    existing: ['amd64', 'arm64'],
    createButton: 'Create Architecture',
    createTitle: 'Create Architecture',
    createLabel: 'Architecture Name',
    editTitle: 'Edit Architecture',
    editLabel: 'Rename Architecture',
    deleteTitle: 'Delete architecture',
    deletePlaceholder: 'Enter architecture name',
    empty: () => (db.archs = []),
    emptyText: 'No architectures have been created yet.',
    notFound: 'No architectures found matching your search.',
    firstId: 'ar-1',
  },
];

describe.each(simpleEntities)('$kind page', (e) => {
  const renderPage = () => renderWithProviders(<e.Page />);
  const [first, second] = e.existing;

  it('lists, searches and shows the empty state', async () => {
    const { user } = renderPage();
    expect(await screen.findByRole('heading', { name: first })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: second })).toBeInTheDocument();
    await user.type(screen.getAllByPlaceholderText('Search...')[0], second.toUpperCase());
    expect(screen.queryByRole('heading', { name: first })).toBeNull();
    await user.type(screen.getAllByPlaceholderText('Search...')[0], 'zzz');
    expect(screen.getByText(e.notFound)).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    e.empty();
    renderPage();
    expect(await screen.findByText(e.emptyText)).toBeInTheDocument();
  });

  it('creates with a trimmed name and refetches', async () => {
    server.use(route('post', `/${e.api}/create`, () => HttpResponse.json({ created: true })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: first });
    await user.click(screen.getAllByRole('button', { name: e.createButton })[0]);
    expect(screen.getByRole('heading', { name: e.createTitle })).toBeInTheDocument();
    const listCalls = callsTo('GET', `/${e.api}/list`).length;
    await user.type(screen.getByLabelText(e.createLabel), '  beta  ');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.queryByRole('heading', { name: e.createTitle })).toBeNull());
    expect(lastCall('POST', `/${e.api}/create`).json).toEqual({ [e.field]: 'beta' });
    await waitFor(() => expect(callsTo('GET', `/${e.api}/list`).length).toBeGreaterThan(listCalls));
  });

  it('does not create a blank name', async () => {
    const { user } = renderPage();
    await screen.findByRole('heading', { name: first });
    await user.click(screen.getAllByRole('button', { name: e.createButton })[0]);
    await user.type(screen.getByLabelText(e.createLabel), '   ');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(callsTo('POST', `/${e.api}/create`)).toHaveLength(0);
    expect(screen.getByRole('heading', { name: e.createTitle })).toBeInTheDocument();
  });

  it('shows the create error', async () => {
    server.use(route('post', `/${e.api}/create`, () => HttpResponse.json({ error: 'already exists' }, { status: 400 })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: first });
    await user.click(screen.getAllByRole('button', { name: e.createButton })[0]);
    await user.type(screen.getByLabelText(e.createLabel), first);
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('already exists')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: e.createTitle })).toBeInTheDocument();
  });

  it('renames from the card', async () => {
    server.use(route('post', `/${e.api}/update`, () => HttpResponse.json({ updated: true })));
    const { user } = renderPage();
    await user.click(await screen.findByRole('heading', { name: first }));
    expect(screen.getByRole('heading', { name: e.editTitle })).toBeInTheDocument();
    const input = screen.getByLabelText(e.editLabel);
    expect(input).toHaveValue(first);
    await user.clear(input);
    await user.type(input, 'renamed');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.queryByRole('heading', { name: e.editTitle })).toBeNull());
    expect(lastCall('POST', `/${e.api}/update`).json).toEqual({ id: e.firstId, [e.field]: 'renamed' });
  });

  it('shows the rename error', async () => {
    server.use(route('post', `/${e.api}/update`, () => HttpResponse.json({ error: 'in use' }, { status: 409 })));
    const { user } = renderPage();
    await user.click(await screen.findByRole('heading', { name: first }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('in use')).toBeInTheDocument();
  });

  it('deletes after typing the name, without opening the editor', async () => {
    server.use(route('delete', `/${e.api}/delete`, () => HttpResponse.json({ deleted: 1 })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: first });
    await user.click(within(card(first)).getByTitle(e.deleteTitle));
    expect(screen.queryByRole('heading', { name: e.editTitle })).toBeNull();
    const confirm = screen.getByRole('button', { name: 'Delete' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByPlaceholderText(e.deletePlaceholder), first);
    await user.click(confirm);
    await waitFor(() => expect(screen.queryByText('Delete confirmation')).toBeNull());
    expect(lastCall('DELETE', `/${e.api}/delete`).query.get('id')).toBe(e.firstId);
  });

  it('shows the delete error', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    server.use(route('delete', `/${e.api}/delete`, () => HttpResponse.json({ error: 'still used by versions' }, { status: 400 })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: first });
    await user.click(within(card(first)).getByTitle(e.deleteTitle));
    await user.type(screen.getByPlaceholderText(e.deletePlaceholder), first);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('still used by versions')).toBeInTheDocument();
    expect(screen.getByText('Delete confirmation')).toBeInTheDocument();
  });
});

describe('platforms page', () => {
  const renderPage = () => renderWithProviders(<PlatformsPage />);

  it('shows updater count and default', async () => {
    renderPage();
    await screen.findByRole('heading', { name: 'windows' });
    expect(within(card('windows')).getByText('2 updaters')).toBeInTheDocument();
    expect(within(card('windows')).getByText('Default: squirrel_windows')).toBeInTheDocument();
    expect(within(card('linux')).getByText('1 updater')).toBeInTheDocument();
  });

  it('creates a platform with picked updaters and default', async () => {
    server.use(route('post', '/platform/create', () => HttpResponse.json({})));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'linux' });
    await user.click(screen.getAllByRole('button', { name: 'Create Platform' })[0]);
    expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled();
    await user.type(screen.getByLabelText('Platform name'), ' macos ');
    await user.click(screen.getByRole('button', { name: 'Expand updaters' }));
    await user.click(screen.getByRole('heading', { name: 'Manual' }));
    await user.click(screen.getByRole('heading', { name: 'Sparkle' }));
    await user.click(screen.getByRole('heading', { name: 'Tauri' }));
    const radios = screen.getAllByRole('radio', { name: 'Set as default' });
    expect(radios).toHaveLength(3);
    await user.click(radios[2]);
    await user.click(screen.getByRole('heading', { name: 'Tauri' }));
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(lastCall('POST', '/platform/create')).toBeDefined());
    expect(lastCall('POST', '/platform/create').json).toEqual({
      platform: 'macos',
      updaters: [
        { type: 'manual', default: true },
        { type: 'sparkle', default: false },
      ],
    });
  });

  it('edits a platform and keeps manual even when the server lost it', async () => {
    db.platforms = [{ ID: 'pl-9', PlatformName: 'mac', Updated_at: '', Updaters: [{ type: 'sparkle', default: true }] }];
    server.use(route('post', '/platform/update', () => HttpResponse.json({})));
    const { user } = renderPage();
    await user.click(await screen.findByRole('heading', { name: 'mac' }));
    expect(screen.getByRole('heading', { name: 'Edit platform' })).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Platform name'));
    await user.type(screen.getByLabelText('Platform name'), 'macos');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(lastCall('POST', '/platform/update')).toBeDefined());
    expect(lastCall('POST', '/platform/update').json).toEqual({
      id: 'pl-9',
      platform: 'macos',
      updaters: [
        { type: 'sparkle', default: true },
        { type: 'manual', default: false },
      ],
    });
  });

  it('keeps the create dialog open and shows the server error', async () => {
    server.use(route('post', '/platform/create', () => HttpResponse.json({ error: 'platform already exists' }, { status: 409 })));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'linux' });
    await user.click(screen.getAllByRole('button', { name: 'Create Platform' })[0]);
    await user.type(screen.getByLabelText('Platform name'), 'linux');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('platform already exists')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Create platform' })).toBeInTheDocument();
  });

  it('keeps the edit dialog open and shows the server error', async () => {
    server.use(route('post', '/platform/update', () => HttpResponse.json({ error: 'platform in use' }, { status: 400 })));
    const { user } = renderPage();
    await user.click(await screen.findByRole('heading', { name: 'linux' }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('platform in use')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Edit platform' })).toBeInTheDocument();
  });

  it('deletes a platform', async () => {
    server.use(route('delete', '/platform/delete', () => HttpResponse.json({})));
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'linux' });
    await user.click(within(card('linux')).getByTitle('Delete platform'));
    await user.type(screen.getByPlaceholderText('Enter platform name'), 'linux');
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(lastCall('DELETE', '/platform/delete')?.query.get('id')).toBe('pl-1'));
  });
});
