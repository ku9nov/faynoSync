import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { callsTo, db, lastCall, route, useFakeApi, version } from '../fakeApi';
import { currentLocation, file } from '../helpers';
import { HomePage } from '@/pages/HomePage';

const renderList = () => renderWithProviders(<HomePage />, { route: '/applications', path: '/applications' });

const appCard = (name: string) => screen.getByRole('heading', { level: 3, name }).closest('.sharedCard') as HTMLElement;

beforeEach(() => useFakeApi());

describe('application list', () => {
  it('shows every app with its feature badges', async () => {
    renderList();
    expect(await screen.findByRole('heading', { level: 3, name: 'alpha' })).toBeInTheDocument();
    const beta = appCard('beta');
    expect(within(beta).getByText('TUF')).toBeInTheDocument();
    expect(within(beta).getByText('Reports')).toBeInTheDocument();
    expect(within(beta).getByText('CDN')).toBeInTheDocument();
    expect(within(appCard('alpha')).queryByText('TUF')).toBeNull();
    expect(within(appCard('alpha')).getByText('First app')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    db.apps = [];
    renderList();
    expect(await screen.findByText('No applications have been created yet.')).toBeInTheDocument();
  });

  it('filters by the header search', async () => {
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.type(screen.getAllByPlaceholderText('Search...')[0], 'BET');
    expect(screen.queryByRole('heading', { level: 3, name: 'alpha' })).toBeNull();
    expect(screen.getByRole('heading', { level: 3, name: 'beta' })).toBeInTheDocument();
    await user.clear(screen.getAllByPlaceholderText('Search...')[0]);
    await user.type(screen.getAllByPlaceholderText('Search...')[0], 'zzz');
    expect(screen.getByText('No applications found matching your search.')).toBeInTheDocument();
  });

  it('pins favorites first and remembers them', async () => {
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    const titles = () => screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent);
    expect(titles()).toEqual(['alpha', 'beta']);
    await user.click(within(appCard('beta')).getByTitle('Add to favorites'));
    expect(titles()).toEqual(['beta', 'alpha']);
    expect(within(appCard('beta')).getByTitle('Remove from favorites')).toHaveAttribute('aria-pressed', 'true');
    expect(JSON.parse(localStorage.getItem('favorite-apps')!)).toEqual(['app-2']);
    expect(currentLocation()).toBe('/applications');
  });

  it('expands long descriptions without opening the app', async () => {
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'beta' });
    await user.click(within(appCard('beta')).getByTitle('Expand'));
    expect(within(appCard('beta')).getByTitle('Collapse')).toBeInTheDocument();
    expect(currentLocation()).toBe('/applications');
  });

  it('opens an app on click', async () => {
    const { user } = renderList();
    await user.click(await screen.findByRole('heading', { level: 3, name: 'alpha' }));
    expect(currentLocation()).toBe('/applications/alpha');
  });
});

describe('create application', () => {
  it('sends the form and refreshes the list', async () => {
    server.use(route('post', '/app/create', () => HttpResponse.json({ createAppResult: { Created: true } })));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(screen.getByRole('button', { name: 'Create app' }));
    expect(screen.getByRole('heading', { name: 'Create Application' })).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('Enter app name'), 'gamma');
    await user.type(screen.getByPlaceholderText('Enter app description'), 'Third');
    await user.click(screen.getByRole('checkbox', { name: /Enable TUF/ }));
    await user.click(screen.getByRole('checkbox', { name: /Enable CDN/ }));
    const listCallsBefore = callsTo('GET', '/app/list').length;
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Create Application' })).toBeNull());
    expect(lastCall('POST', '/app/create').form).toEqual({
      data: { app: 'gamma', description: 'Third', tuf: 'true', reports: 'false', cdn: 'true' },
    });
    await waitFor(() => expect(callsTo('GET', '/app/list').length).toBeGreaterThan(listCallsBefore));
  });

  it('does not refresh the list when creation fails', async () => {
    server.use(route('post', '/app/create', () => HttpResponse.json({ error: 'app exists' }, { status: 409 })));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(screen.getByRole('button', { name: 'Create app' }));
    await user.type(screen.getByPlaceholderText('Enter app name'), 'alpha');
    const listCallsBefore = callsTo('GET', '/app/list').length;
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('app exists')).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 50));
    expect(callsTo('GET', '/app/list')).toHaveLength(listCallsBefore);
    expect(screen.getByRole('heading', { name: 'Create Application' })).toBeInTheDocument();
  });

  it('private apps get a download mode and never a CDN', async () => {
    server.use(route('post', '/app/create', () => HttpResponse.json({})));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(screen.getByRole('button', { name: 'Create app' }));
    await user.type(screen.getByPlaceholderText('Enter app name'), 'secret');
    await user.click(screen.getByRole('checkbox', { name: /Enable CDN/ }));
    await user.click(screen.getByRole('checkbox', { name: /Private app/ }));
    expect(screen.queryByRole('checkbox', { name: /Enable CDN/ })).toBeNull();
    await user.click(screen.getByRole('radio', { name: /Unlisted/ }));
    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(lastCall('POST', '/app/create')).toBeDefined());
    expect(lastCall('POST', '/app/create').form?.data).toEqual({
      app: 'secret',
      description: '',
      private: 'true',
      download_mode: 'unlisted',
      tuf: 'false',
      reports: 'false',
      cdn: 'false',
    });
  });

  it('uploads the logo', async () => {
    server.use(route('post', '/app/create', () => HttpResponse.json({})));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(screen.getByRole('button', { name: 'Create app' }));
    await user.type(screen.getByPlaceholderText('Enter app name'), 'logo-app');
    await user.upload(screen.getByLabelText('Choose files to upload'), new File(['png'], 'logo.png', { type: 'image/png' }));
    expect(screen.getByText('logo.png')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(lastCall('POST', '/app/create')?.files).toEqual(['file:logo.png']));
  });

  it('keeps the modal open and shows the server error', async () => {
    server.use(
      route('post', '/app/create', () =>
        HttpResponse.json({ error: 'app already exists', details: 'duplicate key' }, { status: 400 }),
      ),
    );
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(screen.getByRole('button', { name: 'Create app' }));
    await user.type(screen.getByPlaceholderText('Enter app name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('app already exists')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show details' }));
    expect(screen.getByText('duplicate key')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Create Application' })).toBeInTheDocument();
  });
});

describe('edit application', () => {
  it('prefills and saves the app', async () => {
    server.use(route('post', '/app/update', () => HttpResponse.json({})));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'beta' });
    await user.click(within(appCard('beta')).getByTitle('Edit app'));

    expect(screen.getByPlaceholderText('Enter app name')).toHaveValue('beta');
    expect(screen.getByRole('checkbox', { name: /Enable TUF/ })).toBeChecked();
    expect(screen.queryByRole('checkbox', { name: /Enable CDN/ })).toBeNull();
    expect(screen.getByRole('radio', { name: /Strict/ })).toBeChecked();

    await user.clear(screen.getByPlaceholderText('Enter app description'));
    await user.type(screen.getByPlaceholderText('Enter app description'), 'Updated');
    await user.click(screen.getByRole('checkbox', { name: /Enable reports/ }));
    await user.click(screen.getByRole('radio', { name: /Unlisted/ }));
    await user.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Edit Application' })).toBeNull());
    expect(lastCall('POST', '/app/update').form?.data).toEqual({
      id: 'app-2',
      app: 'beta',
      description: 'Updated',
      tuf: 'true',
      reports: 'false',
      cdn: 'true',
      download_mode: 'unlisted',
    });
    expect(currentLocation()).toBe('/applications');
  });

  it('shows the update error', async () => {
    server.use(route('post', '/app/update', () => HttpResponse.json({ error: 'forbidden' }, { status: 403 })));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(within(appCard('alpha')).getByTitle('Edit app'));
    await user.click(screen.getByRole('button', { name: 'Update' }));
    expect(await screen.findByText('forbidden')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Edit Application' })).toBeInTheDocument();
  });
});

describe('edit application logo', () => {
  const openEdit = async () => {
    const utils = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await utils.user.click(within(appCard('alpha')).getByTitle('Edit app'));
    return utils;
  };
  const logoInput = () => document.getElementById('file-upload') as HTMLInputElement;

  it('uploads a new logo with the update', async () => {
    server.use(route('post', '/app/update', () => HttpResponse.json({})));
    const { user } = await openEdit();
    await user.upload(logoInput(), file('old.png', 'x'.repeat(2048), 'image/png'));
    expect(screen.getByText('old.png')).toBeInTheDocument();
    expect(screen.getByText('2 KB')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove file' }));
    expect(screen.queryByText('old.png')).toBeNull();
    await user.upload(logoInput(), file('logo.png', 'png', 'image/png'));
    expect(screen.getByText('3 Bytes')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(lastCall('POST', '/app/update')).toBeDefined());
    expect(lastCall('POST', '/app/update').files).toEqual(['file:logo.png']);
  });

  it('shows a network failure with details', async () => {
    server.use(route('post', '/app/update', () => HttpResponse.error()));
    const { user } = await openEdit();
    await user.click(screen.getByRole('button', { name: 'Update' }));
    expect(await screen.findByText('Failed to update application')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show details' }));
    expect(screen.getByText('Network Error')).toBeInTheDocument();
  });
});

describe('delete application', () => {
  it('requires typing the name, then deletes by id', async () => {
    server.use(route('delete', '/app/delete', () => HttpResponse.json({ deleteAppResult: 1 })));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    await user.click(within(appCard('alpha')).getByTitle('Delete app'));
    expect(screen.getByText('To delete application "alpha" please enter its name:')).toBeInTheDocument();
    const remove = screen.getByRole('button', { name: 'Delete' });
    expect(remove).toBeDisabled();
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alph');
    expect(remove).toBeDisabled();
    await user.type(screen.getByPlaceholderText('Enter application name'), 'a');
    expect(remove).toBeEnabled();
    await user.click(remove);
    await waitFor(() => expect(screen.queryByText('Delete confirmation')).toBeNull());
    expect(lastCall('DELETE', '/app/delete').query.get('id')).toBe('app-1');
  });

  it('shows the delete error and keeps the dialog', async () => {
    server.use(route('delete', '/app/delete', () => HttpResponse.json({ error: 'app has versions' }, { status: 400 })));
    const { user } = renderList();
    await screen.findByRole('heading', { level: 3, name: 'alpha' });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await user.click(within(appCard('alpha')).getByTitle('Delete app'));
    await user.type(screen.getByPlaceholderText('Enter application name'), 'alpha');
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('app has versions')).toBeInTheDocument();
    expect(screen.getByText('Delete confirmation')).toBeInTheDocument();
  });
});
