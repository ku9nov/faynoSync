import { useMemo } from 'react';

export const useSearch = <T extends { ID: string }>(items: T[], searchTerm: string): T[] => {
  return useMemo(() => {
    if (!searchTerm) return items;
    if (!items) return [];

    const lowerSearchTerm = searchTerm.toLowerCase();
    return items.filter(item => {
      return Object.values(item).some(value => {
        if (typeof value === 'string') {
          return value.toLowerCase().includes(lowerSearchTerm);
        }
        return false;
      });
    });
  }, [items, searchTerm]);
}; 