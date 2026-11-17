import { describe, expect, it, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { getAppInitials, getAppTileStyle } from '@/utils/appLogo';
import { getPlatformIcon, isKnownPlatform } from '@/utils/platformIcon';
import { generateRandomPassword } from '@/utils/password';
import { copyToClipboard } from '@/utils/clipboard';
import { useSearch } from '@/hooks/useSearch';
import { useToast } from '@/hooks/useToast';
import { toast } from 'react-toastify';
import { useFavoriteApps } from '@/hooks/useFavoriteApps';
import { normalizeKeyAlgorithm } from '@/components/settings/tuf/keyAlgorithm';
import { getStatusColor, getStatusIcon, getTaskStateColor } from '@/components/settings/tuf/utils';

describe('getAppInitials', () => {
  it.each([
    ['super-wallet', 'SW'],
    ['faynoSync', 'FS'],
    ['updater', 'UP'],
    ['my app 2', 'MA'],
    ['x', 'X'],
    ['---', '?'],
    ['', '?'],
  ])('%s -> %s', (name, expected) => {
    expect(getAppInitials(name)).toBe(expected);
  });
});

describe('getAppTileStyle', () => {
  it('is stable for the same name', () => {
    expect(getAppTileStyle('faynoSync')).toBe(getAppTileStyle('faynoSync'));
  });

  it('spreads names over more than one style', () => {
    const styles = new Set(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map(getAppTileStyle));
    expect(styles.size).toBeGreaterThan(1);
  });
});

describe('getPlatformIcon', () => {
  it.each([
    ['windows', 'fab fa-windows'],
    ['Win32', 'fab fa-windows'],
    ['win', 'fab fa-windows'],
    ['darwin', 'fab fa-apple'],
    ['Mac OS X', 'fab fa-apple'],
    ['aarch64-apple-darwin', 'fab fa-apple'],
    ['GNU/Linux', 'fab fa-linux'],
    ['x86_64-unknown-linux-gnu', 'fab fa-linux'],
    ['ubuntu', 'fab fa-ubuntu'],
    ['ios', 'fab fa-app-store-ios'],
    ['android', 'fab fa-android'],
    ['docker', 'fab fa-docker'],
  ])('%s -> %s', (platform, icon) => {
    expect(getPlatformIcon(platform)).toBe(icon);
    expect(isKnownPlatform(platform)).toBe(true);
  });

  it.each(['studios', 'aarch64', 'twinkle', 'macaroni', 'something', '', null, undefined])(
    'falls back for %s',
    (platform) => {
      expect(getPlatformIcon(platform)).toBe('fas fa-cube');
      expect(isKnownPlatform(platform)).toBe(false);
    },
  );
});

describe('generateRandomPassword', () => {
  it('has the requested length and alphanumeric charset', () => {
    expect(generateRandomPassword()).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(generateRandomPassword(5)).toMatch(/^[A-Za-z0-9]{5}$/);
    expect(generateRandomPassword(100)).toHaveLength(100);
  });

  it('is not repeated', () => {
    expect(generateRandomPassword()).not.toBe(generateRandomPassword());
  });

  it('drops biased bytes instead of folding them into the charset', () => {
    const spy = vi.spyOn(crypto, 'getRandomValues');
    let call = 0;
    spy.mockImplementation(((array: Uint8Array) => {
      array.fill(call++ === 0 ? 255 : 0);
      return array;
    }) as typeof crypto.getRandomValues);
    expect(generateRandomPassword(4)).toBe('aaaa');
    expect(call).toBe(2);
  });
});

describe('copyToClipboard', () => {
  it('uses the Clipboard API in a secure context', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await expect(copyToClipboard('hello')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('hello');
  });

  it('falls back to execCommand when the Clipboard API is missing', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;
    await expect(copyToClipboard('hello')).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(document.querySelector('input')).toBeNull();
  });

  it('shows a manual-copy overlay when execCommand fails', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    document.execCommand = vi.fn().mockReturnValue(false);
    await expect(copyToClipboard('secret text')).resolves.toBe(true);
    const textarea = document.querySelector('textarea.temp-clipboard-element') as HTMLTextAreaElement;
    expect(textarea.value).toBe('secret text');
    (document.querySelector('button.temp-clipboard-element') as HTMLButtonElement).click();
    expect(document.querySelectorAll('.temp-clipboard-element')).toHaveLength(0);
  });
});

describe('useSearch', () => {
  const items = [
    { ID: '1', name: 'Alpha', channel: 'stable', count: 7 },
    { ID: '2', name: 'Beta', channel: 'nightly', count: 77 },
  ];

  it('returns all items for an empty term', () => {
    const { result } = renderHook(() => useSearch(items, ''));
    expect(result.current).toBe(items);
  });

  it('matches any string field case-insensitively', () => {
    expect(renderHook(() => useSearch(items, 'NIGHT')).result.current).toEqual([items[1]]);
    expect(renderHook(() => useSearch(items, 'alp')).result.current).toEqual([items[0]]);
  });

  it('ignores non-string fields', () => {
    expect(renderHook(() => useSearch(items, '77')).result.current).toEqual([]);
  });
});

describe('useFavoriteApps', () => {
  it('toggles and persists favorites', () => {
    const { result } = renderHook(() => useFavoriteApps());
    act(() => result.current.toggleFavorite('a'));
    act(() => result.current.toggleFavorite('b'));
    act(() => result.current.toggleFavorite('a'));
    expect([...result.current.favorites]).toEqual(['b']);
    expect(JSON.parse(localStorage.getItem('favorite-apps')!)).toEqual(['b']);
  });

  it('ignores corrupt storage', () => {
    localStorage.setItem('favorite-apps', '{not json');
    expect(renderHook(() => useFavoriteApps()).result.current.favorites.size).toBe(0);
    localStorage.setItem('favorite-apps', JSON.stringify(['x', 5, null]));
    expect([...renderHook(() => useFavoriteApps()).result.current.favorites]).toEqual(['x']);
  });

  it('syncs with other tabs through the storage event', () => {
    const { result } = renderHook(() => useFavoriteApps());
    localStorage.setItem('favorite-apps', JSON.stringify(['from-other-tab']));
    act(() => {
      window.dispatchEvent(new StorageEvent('storage', { key: 'favorite-apps' }));
    });
    expect([...result.current.favorites]).toEqual(['from-other-tab']);
  });
});

describe('normalizeKeyAlgorithm', () => {
  it.each([
    ['ed25519', 'ed25519'],
    [' RSA ', 'rsa'],
    ['ECDSA', 'ecdsa'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeKeyAlgorithm(input)).toBe(expected);
  });

  it.each(['dsa', '', undefined])('rejects %s', (input) => {
    expect(() => normalizeKeyAlgorithm(input)).toThrow(/Unsupported key type/);
  });
});

describe('TUF status helpers', () => {
  it('maps step statuses', () => {
    expect(getStatusColor('success')).toBe('text-green-500');
    expect(getStatusColor('error')).toBe('text-red-500');
    expect(getStatusColor('disabled')).toBe('text-gray-500');
    expect(getStatusIcon('in-progress')).toContain('fa-spin');
    expect(getStatusIcon('error')).toBe('fa-times-circle');
  });

  it('maps task states', () => {
    expect(getTaskStateColor('SUCCESS')).toBe('text-green-500');
    expect(getTaskStateColor('FAILURE')).toBe('text-red-500');
    expect(getTaskStateColor('PENDING')).toBe('text-yellow-500');
  });
});

describe('useToast', () => {
  it.each([
    ['toastSuccess', 'success'],
    ['toastError', 'error'],
    ['toastWarn', 'warn'],
    ['toastInfo', 'info'],
  ] as const)('%s uses toast.%s', (fn, kind) => {
    const spy = vi.spyOn(toast, kind).mockReturnValue('id');
    const { result } = renderHook(() => useToast());
    result.current[fn]('hello');
    expect(spy).toHaveBeenCalledWith('hello', expect.objectContaining({ autoClose: 3000 }));
  });
});
