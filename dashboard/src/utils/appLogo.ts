// Hues deliberately outside the status palette (green / red / amber): a tile colour
// carries identity, not state, and must not read as a badge.
const TILE_STYLES = [
  'bg-violet-500/30 border-violet-400/45 text-violet-100',
  'bg-indigo-500/30 border-indigo-400/45 text-indigo-100',
  'bg-fuchsia-500/30 border-fuchsia-400/45 text-fuchsia-100',
  'bg-sky-500/30 border-sky-400/45 text-sky-100',
  'bg-teal-500/30 border-teal-400/45 text-teal-100',
  'bg-purple-500/30 border-purple-400/45 text-purple-100',
];

// "super-wallet" -> SW, "faynoSync" -> FS, "updater" -> UP
export const getAppInitials = (name: string): string => {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean);

  if (words.length === 0) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
};

export const getAppTileStyle = (name: string): string => {
  let hash = 5381;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) + hash + name.charCodeAt(i)) | 0;
  }
  return TILE_STYLES[Math.abs(hash) % TILE_STYLES.length];
};
