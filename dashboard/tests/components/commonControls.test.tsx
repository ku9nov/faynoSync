import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useState } from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse } from 'msw';
import { server } from '../msw';
import { renderWithProviders } from '../render';
import { route, useFakeApi } from '../fakeApi';
import { Dropdown } from '@/components/common/Dropdown';
import { ActionIcons } from '@/components/ActionIcons';
import { DownloadArtifactsModal } from '@/components/modals/DownloadArtifactsModal';
import type { Artifact } from '@/hooks/use-query/useAppsQuery';

const options = [
  { value: 'a', label: 'Alpha' },
  { value: 'b', label: 'Beta', icon: 'fas fa-b' },
  { value: 'c', label: 'Gamma' },
];

const Single = ({ initial = '', onChange = vi.fn() }: { initial?: string; onChange?: (v: string) => void }) => {
  const [value, setValue] = useState(initial);
  return (
    <>
      <Dropdown
        ariaLabel="Pick"
        options={options}
        value={value}
        onChange={(v) => {
          setValue(v);
          onChange(v);
        }}
      />
      <button type="button">outside</button>
    </>
  );
};

const Multi = () => {
  const [value, setValue] = useState<string[]>([]);
  return (
    <Dropdown
      ariaLabel="Pick many"
      multiple
      placeholder="None"
      options={options}
      value={value}
      onChange={(v) => setValue((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]))}
    />
  );
};

describe('Dropdown', () => {
  const combobox = () => screen.getByRole('combobox');
  const active = () => {
    const id = combobox().getAttribute('aria-activedescendant');
    return id ? document.getElementById(id)?.textContent : null;
  };

  it('opens on the selected option and walks the list with the keyboard', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Single initial="b" onChange={onChange} />);
    expect(combobox()).toHaveTextContent('Beta');
    combobox().focus();
    await user.keyboard('{ArrowDown}');
    expect(combobox()).toHaveAttribute('aria-expanded', 'true');
    expect(active()).toBe('Beta');
    await user.keyboard('{ArrowDown}');
    expect(active()).toBe('Gamma');
    await user.keyboard('{ArrowDown}');
    expect(active()).toBe('Alpha');
    await user.keyboard('{ArrowUp}');
    expect(active()).toBe('Gamma');
    await user.keyboard('{Home}');
    expect(active()).toBe('Alpha');
    await user.keyboard('{End}');
    expect(active()).toBe('Gamma');
    await user.keyboard('{Enter}');
    expect(onChange).toHaveBeenCalledWith('c');
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(combobox()).toHaveFocus();
    expect(combobox()).toHaveTextContent('Gamma');
  });

  it('starts at the first option when nothing is selected', async () => {
    const user = userEvent.setup();
    render(<Single />);
    expect(combobox()).toHaveTextContent('Select');
    combobox().focus();
    await user.keyboard(' ');
    expect(active()).toBe('Alpha');
    await user.keyboard('{ArrowUp}');
    expect(active()).toBe('Gamma');
  });

  it('closes on Escape with focus back on the trigger, and on Tab', async () => {
    const user = userEvent.setup();
    render(<Single />);
    await user.click(combobox());
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(combobox()).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await user.keyboard('{Tab}');
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('closes on a click outside and toggles on the trigger', async () => {
    const user = userEvent.setup();
    render(<Single />);
    await user.click(combobox());
    await user.click(screen.getByRole('button', { name: 'outside' }));
    expect(screen.queryByRole('listbox')).toBeNull();
    await user.click(combobox());
    await user.click(combobox());
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('highlights on hover and keeps a multi-select open', async () => {
    const user = userEvent.setup();
    render(<Multi />);
    expect(combobox()).toHaveTextContent('None');
    await user.click(combobox());
    await user.hover(screen.getByRole('option', { name: 'Gamma' }));
    expect(active()).toBe('Gamma');
    await user.click(screen.getByRole('option', { name: 'Alpha' }));
    await user.click(screen.getByRole('option', { name: 'Gamma' }));
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    expect(combobox()).toHaveTextContent('2 selected');
    expect(screen.getByRole('option', { name: 'Alpha' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('option', { name: 'Beta' })).toHaveAttribute('aria-selected', 'false');
  });

  it('returns focus to the trigger when Escape closes the list from an option', async () => {
    const user = userEvent.setup();
    render(<Multi />);
    await user.click(combobox());
    await user.click(screen.getByRole('option', { name: 'Beta' }));
    expect(screen.getByRole('option', { name: 'Beta' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(combobox()).toHaveFocus();
  });

  it('shows the empty message and ignores keys when disabled', async () => {
    const user = userEvent.setup();
    const { rerender } = render(<Dropdown options={[]} value="" onChange={vi.fn()} emptyMessage="Nothing here" />);
    await user.click(combobox());
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    await user.keyboard('{ArrowDown}{Enter}');
    rerender(<Dropdown options={options} value="" onChange={vi.fn()} disabled />);
    expect(combobox()).toBeDisabled();
  });
});

describe('ActionIcons', () => {
  beforeEach(() => {
    useFakeApi();
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
  });

  afterEach(() => {
    Reflect.deleteProperty(window, 'isSecureContext');
  });

  const renderIcons = (props: Partial<Parameters<typeof ActionIcons>[0]> = {}) => {
    const handlers = { onDownload: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn() };
    const utils = renderWithProviders(<ActionIcons {...handlers} artifactLink="http://localhost:3000/download/x.bin" {...props} />);
    return { ...utils, ...handlers };
  };

  it('copies the signed download url when the link resolves to one', async () => {
    server.use(route('get', '/download/x.bin', () => HttpResponse.json({ download_url: 'https://cdn.example/x.bin?sig=1' })));
    const { user } = renderIcons();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy link' }));
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith('https://cdn.example/x.bin?sig=1');
  });

  it.each([
    ['a plain file', () => new HttpResponse('bytes')],
    ['an error', () => HttpResponse.json({}, { status: 403 })],
  ])('copies the original link for %s', async (_, resolver) => {
    server.use(route('get', '/download/x.bin', resolver));
    const { user } = renderIcons();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy link' }));
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith('http://localhost:3000/download/x.bin');
  });

  it('wires download, edit and delete without bubbling to the card', async () => {
    const onCard = vi.fn();
    const handlers = { onDownload: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn() };
    const user = userEvent.setup();
    render(
      <div onClick={onCard}>
        <ActionIcons {...handlers} />
      </div>,
    );
    expect(screen.queryByRole('button', { name: 'Copy link' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Download' }));
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(handlers.onDownload).toHaveBeenCalledTimes(1);
    expect(handlers.onEdit).toHaveBeenCalledTimes(1);
    expect(handlers.onDelete).toHaveBeenCalledTimes(1);
    expect(onCard).not.toHaveBeenCalled();
  });

  it('removes a leftover manual-copy overlay on unmount', () => {
    const { unmount } = renderIcons();
    const overlay = document.createElement('textarea');
    overlay.className = 'temp-clipboard-element';
    document.body.appendChild(overlay);
    unmount();
    expect(document.querySelector('.temp-clipboard-element')).toBeNull();
  });

  it('hides download and copy when there is nothing to download', () => {
    renderIcons({ showDownload: false });
    expect(screen.queryByRole('button', { name: 'Download' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Copy link' })).toBeNull();
  });
});

describe('DownloadArtifactsModal', () => {
  beforeEach(() => {
    useFakeApi();
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
  });

  afterEach(() => {
    Reflect.deleteProperty(window, 'isSecureContext');
  });

  const artifacts = [
    { link: 'http://localhost:3000/download/a.deb', platform: 'linux', arch: 'amd64', package: '.deb', TufTaskID: 't1', TufSigned: true },
    { link: 'http://localhost:3000/download/b.exe', platform: 'windows', arch: 'arm64', package: '.exe', TufTaskID: 't2', TufSigned: false },
  ] as unknown as Artifact[];

  const renderModal = () => {
    const onClose = vi.fn();
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    const utils = renderWithProviders(<DownloadArtifactsModal artifacts={artifacts} onClose={onClose} />);
    return { ...utils, onClose, open };
  };
  const row = (platform: string) => screen.getByText(platform).closest('.cursor-pointer') as HTMLElement;

  it('lists every artifact with its TUF state', () => {
    renderModal();
    expect(screen.getByRole('heading', { name: 'Download artifact' })).toBeInTheDocument();
    expect(within(row('linux')).getByText('signed')).toBeInTheDocument();
    expect(within(row('windows')).getByText('unsigned')).toBeInTheDocument();
    expect(within(row('windows')).getByText('http://localhost:3000/download/b.exe')).toBeInTheDocument();
  });

  it.each([
    ['a signed url', () => HttpResponse.json({ download_url: 'https://cdn.example/b.exe?sig=2' }), 'https://cdn.example/b.exe?sig=2'],
    ['a plain file', () => new HttpResponse('bytes'), 'http://localhost:3000/download/b.exe'],
    ['an auth error', () => HttpResponse.json({}, { status: 401 }), 'http://localhost:3000/download/b.exe'],
  ])('opens %s and closes', async (_, resolver, expected) => {
    server.use(route('get', '/download/b.exe', resolver));
    const { user, onClose, open } = renderModal();
    await user.click(row('windows'));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(open).toHaveBeenCalledWith(expected, '_blank', 'noopener,noreferrer');
  });

  it('stays open and explains a missing download', async () => {
    server.use(route('get', '/download/b.exe', () => HttpResponse.json({}, { status: 404 })));
    const { user, onClose, open } = renderModal();
    await user.click(row('windows'));
    expect(await screen.findByText('Download is not available.')).toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('copies the signed url for one row without opening it', async () => {
    server.use(route('get', '/download/b.exe', () => HttpResponse.json({ download_url: 'https://cdn.example/b.exe?sig=2' })));
    const { user, open, onClose } = renderModal();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(within(row('windows')).getByRole('button', { name: 'Copy link' }));
    expect(await within(row('windows')).findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(within(row('linux')).getByRole('button', { name: 'Copy link' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith('https://cdn.example/b.exe?sig=2');
    expect(open).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it.each([
    [404, 'Download is not available.', undefined],
    [500, null, 'http://localhost:3000/download/a.deb'],
  ])('copy link on HTTP %i', async (status, message, copied) => {
    server.use(route('get', '/download/a.deb', () => HttpResponse.json({}, { status })));
    const { user } = renderModal();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(within(row('linux')).getByRole('button', { name: 'Copy link' }));
    if (message) {
      expect(await screen.findByText(message)).toBeInTheDocument();
      expect(writeText).not.toHaveBeenCalled();
    } else {
      expect(await within(row('linux')).findByRole('button', { name: 'Copied' })).toBeInTheDocument();
      expect(writeText).toHaveBeenCalledWith(copied);
    }
  });

  it('closes from the close button', async () => {
    const { user, onClose } = renderModal();
    const header = screen.getByRole('heading', { name: 'Download artifact' }).parentElement as HTMLElement;
    await user.click(within(header).getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalled();
  });
});
