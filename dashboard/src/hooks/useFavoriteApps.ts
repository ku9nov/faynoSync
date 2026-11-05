import React from 'react';

const storageKey = 'favorite-apps';

const readFavorites = (): string[] => {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(storageKey) || '[]');
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === 'string') : [];
  } catch {
    return [];
  }
};

export const useFavoriteApps = () => {
  const [favorites, setFavorites] = React.useState<Set<string>>(() => new Set(readFavorites()));

  React.useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === storageKey) setFavorites(new Set(readFavorites()));
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  React.useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify([...favorites]));
    } catch {
      // storage unavailable: keep in-memory state only
    }
  }, [favorites]);

  const toggleFavorite = React.useCallback((id: string) => {
    setFavorites(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  return { favorites, toggleFavorite };
};
