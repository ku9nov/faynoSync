import React, { useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/providers/authProvider';
import { useTheme } from '@/providers/themeProvider';
import { useUsersQuery } from '@/hooks/use-query/useUsersQuery';
import { STATUS_BADGE, STATUS_DOT } from '@/components/common/ui';

const THEME_OPTIONS = [
  { mode: 'light' as const, label: 'Light', icon: 'fa-sun' },
  { mode: 'dark' as const, label: 'Dark', icon: 'fa-moon' },
  { mode: 'auto' as const, label: 'Auto', icon: 'fa-clock' },
];

interface SettingsMenuProps {
  onClose: () => void;
  onOpenProfileModal: () => void;
}

export const SettingsMenu: React.FC<SettingsMenuProps> = ({ onClose, onOpenProfileModal }) => {
  const navigate = useNavigate();
  const menuRef = React.useRef<HTMLDivElement>(null);
  const { logout } = useAuth();
  const { themeMode, setThemeMode } = useTheme();
  const { data: userData } = useUsersQuery();
  const [showSettingsModal] = useState(false);
  const [menuPosition, setMenuPosition] = useState({ top: 0, right: 0 });

  React.useEffect(() => {
    // Calculate position for the menu
    const settingsButton = document.querySelector('[aria-label="Settings"]') as HTMLElement;
    if (settingsButton) {
      const rect = settingsButton.getBoundingClientRect();
      setMenuPosition({
        top: rect.bottom + 8,
        right: window.innerWidth - rect.right
      });
    }
  }, []);

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (showSettingsModal) {
        return;
      }
      
      // Check if click was on the settings button
      const settingsButton = document.querySelector('[aria-label="Settings"]');
      if (settingsButton?.contains(event.target as Node)) {
        return;
      }
      
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [onClose, showSettingsModal]);

  React.useEffect(() => {
    const handleViewportChange = () => {
      onClose();
    };

    window.addEventListener('resize', handleViewportChange);
    document.addEventListener('scroll', handleViewportChange, true);

    return () => {
      window.removeEventListener('resize', handleViewportChange);
      document.removeEventListener('scroll', handleViewportChange, true);
    };
  }, [onClose]);

  const handleLogout = () => {
    logout();
    onClose();
  };

  const handleProfileClick = () => {
    onClose();
    onOpenProfileModal();
  };

  const handleSettingsClick = () => {
    onClose();
    // Navigate to Settings page
    navigate('/settings');
  };

  const menuContent = (
    <div
      ref={menuRef}
      className="settings-popup animate-fade-in settings-menu-popup"
      style={{
        position: 'fixed',
        zIndex: 9999,
        top: menuPosition.top,
        right: menuPosition.right,
        width: '15rem',
      }}
    >
      {userData && (
        <>
          <div className="px-2.5 pb-1 pt-2">
            <p className="text-sm font-extrabold tracking-tight text-theme-primary">{userData.username}</p>
            <span
              className={`${STATUS_BADGE} mt-1.5 px-2 py-0.5 text-[11px] ${
                userData.is_admin
                  ? 'text-amber-300 border-amber-500/45'
                  : 'text-violet-300 border-violet-400/50'
              }`}
            >
              <span className={`${STATUS_DOT} ${userData.is_admin ? 'bg-amber-500' : 'bg-violet-400'}`}></span>
              {userData.is_admin ? 'Administrator' : 'Team user'}
            </span>
          </div>
          <div className="settings-popup-divider"></div>
        </>
      )}

      <button onClick={handleProfileClick} className="settings-popup-button">
        <i className="fas fa-user"></i>
        <span>Profile</span>
      </button>
      {userData?.is_admin && (
        <button onClick={handleSettingsClick} className="settings-popup-button">
          <i className="fas fa-cog"></i>
          <span>Settings</span>
        </button>
      )}

      <p className="settings-popup-label">Theme</p>
      <div className="settings-popup-theme" role="group" aria-label="Theme">
        {THEME_OPTIONS.map(({ mode, label, icon }) => (
          <button
            key={mode}
            type="button"
            onClick={() => setThemeMode(mode)}
            aria-pressed={themeMode === mode}
            className={themeMode === mode ? 'is-active' : undefined}
          >
            <i className={`fas ${icon}`}></i>
            {label}
          </button>
        ))}
      </div>

      <div className="settings-popup-divider"></div>
      <button onClick={handleLogout} className="settings-popup-button danger">
        <i className="fas fa-sign-out-alt"></i>
        <span>Logout</span>
      </button>
    </div>
  );

  return <>{createPortal(menuContent, document.body)}</>;
};
