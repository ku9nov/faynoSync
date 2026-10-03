import React, { createContext, useContext, useEffect, useState } from 'react';

type Theme = 'light' | 'dark';
type ThemeMode = 'light' | 'dark' | 'auto';

interface ThemeContextType {
  theme: Theme;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

const isNightTime = (): boolean => {
  const currentHour = new Date().getHours();
  return currentHour >= 20 || currentHour < 6; // Consider night time from 8 PM to 6 AM
};

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    const savedMode = localStorage.getItem('themeMode') as ThemeMode;
    return savedMode || 'auto';
  });

  const [theme, setTheme] = useState<Theme>(() => {
    if (themeMode === 'auto') {
      if (isNightTime()) {
        return 'dark';
      }
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
      }
      return 'light';
    }
    return themeMode;
  });

  useEffect(() => {
    localStorage.setItem('themeMode', themeMode);
    
    if (themeMode === 'auto') {
      const shouldBeDark = isNightTime();
      setTheme(shouldBeDark ? 'dark' : 'light');
    } else {
      setTheme(themeMode);
    }
  }, [themeMode]);

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  // Check time periodically and update theme only in auto mode
  useEffect(() => {
    if (themeMode !== 'auto') return;

    const checkTimeAndUpdateTheme = () => {
      const shouldBeDark = isNightTime();
      setTheme(shouldBeDark ? 'dark' : 'light');
    };

    checkTimeAndUpdateTheme();
    const interval = setInterval(checkTimeAndUpdateTheme, 60000);
    return () => clearInterval(interval);
  }, [themeMode]);

  return (
    <ThemeContext.Provider value={{ theme, themeMode, setThemeMode }}>
      {children}
    </ThemeContext.Provider>
  );
}; 