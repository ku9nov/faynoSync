import { useMemo } from 'react';

type SearchableItem = {
  ID: string;
  [key: string]: any;
};

export const useSearch = (items: SearchableItem[], searchTerm: string): SearchableItem[] => {
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