const FALLBACK_ICON = 'fas fa-cube';

// Platform names are user-defined, and every toolchain spells them differently:
// Electron reports win32/darwin, Go reports windows/darwin, installers report
// macosx/osx. Add an alias here and it propagates everywhere the icon is used.
// Keys must be normalized form: lowercase, alphanumerics only (see normalize).
const PLATFORM_ICONS: Record<string, string> = {
  // Windows
  windows: 'fab fa-windows',
  win: 'fab fa-windows',
  win32: 'fab fa-windows',
  win64: 'fab fa-windows',
  winnt: 'fab fa-windows',
  mswindows: 'fab fa-windows',

  // macOS
  darwin: 'fab fa-apple',
  mac: 'fab fa-apple',
  macos: 'fab fa-apple',
  macosx: 'fab fa-apple',
  osx: 'fab fa-apple',
  apple: 'fab fa-apple',

  // iOS
  ios: 'fab fa-app-store-ios',
  ipados: 'fab fa-app-store-ios',

  // Linux — generic plus the distros that ship their own artifacts
  linux: 'fab fa-linux',
  gnulinux: 'fab fa-linux',
  ubuntu: 'fab fa-ubuntu',
  debian: 'fab fa-linux',
  fedora: 'fab fa-fedora',
  centos: 'fab fa-centos',
  rhel: 'fab fa-redhat',
  redhat: 'fab fa-redhat',
  suse: 'fab fa-suse',
  opensuse: 'fab fa-suse',
  alpine: 'fab fa-linux',
  arch: 'fab fa-linux',
  archlinux: 'fab fa-linux',
  raspbian: 'fab fa-raspberry-pi',
  raspberrypi: 'fab fa-raspberry-pi',

  // BSD
  freebsd: 'fab fa-freebsd',
  openbsd: 'fas fa-server',
  netbsd: 'fas fa-server',

  // Mobile & container
  android: 'fab fa-android',
  docker: 'fab fa-docker',
};

// Too short or too generic to be looked for inside a longer name: "win" is in
// darwin, "arch" is in aarch64, "ios" is in studios. They stay exact-match only.
const AMBIGUOUS_KEYS = new Set(['win', 'mac', 'osx', 'arch', 'ios']);

// Longest first, so "linux-musl" picks linuxmusl over linux and
// "aarch64-apple-darwin" picks darwin over apple.
const SUBSTRING_KEYS = Object.keys(PLATFORM_ICONS)
  .filter(key => !AMBIGUOUS_KEYS.has(key))
  .sort((a, b) => b.length - a.length);

// Collapses spelling variants so the map only needs one key per alias:
// "Mac OS X" -> macosx, "win-32" -> win32, "GNU/Linux" -> gnulinux
const normalize = (platform: string): string =>
  platform.toLowerCase().replace(/[^a-z0-9]/g, '');

// Exact alias wins; otherwise fall back to a substring match so compound names
// the map can't enumerate ("linux-musl", "x86_64-unknown-linux-gnu") still resolve.
const resolveIcon = (platform: string): string | null => {
  const normalized = normalize(platform);
  const exact = PLATFORM_ICONS[normalized];
  if (exact) return exact;

  const matched = SUBSTRING_KEYS.find(key => normalized.includes(key));
  return matched ? PLATFORM_ICONS[matched] : null;
};

export const getPlatformIcon = (platform?: string | null): string => {
  if (!platform) return FALLBACK_ICON;
  return resolveIcon(platform) ?? FALLBACK_ICON;
};

export const isKnownPlatform = (platform?: string | null): boolean =>
  !!platform && resolveIcon(platform) !== null;
