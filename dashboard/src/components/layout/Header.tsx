import React from 'react';
import { SettingsMenu } from '@/components/layout/SettingsMenu';
import useMediaQuery from '@/hooks/useMediaQuery';
import '@/styles/header.css';
import { SettingsModal } from '@/components/modals/SettingsModal';
import { ProfileModal } from '@/components/modals/ProfileModal';

interface HeaderProps {
  title: string;
  titleContent?: React.ReactNode;
  onCreateClick: () => void;
  createButtonText: string;
  additionalButton?: React.ReactNode;
  onSearchChange?: (searchTerm: string) => void;
  hideSearch?: boolean;
  onMenuClick?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  titleContent,
  onCreateClick,
  createButtonText,
  additionalButton,
  onSearchChange,
  hideSearch = false,
  onMenuClick
}) => {
  const [showSettings, setShowSettings] = React.useState(false);
  const [showSettingsModal, setShowSettingsModal] = React.useState(false);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [showProfileModal, setShowProfileModal] = React.useState(false);
  const isMobile = useMediaQuery('(max-width: 767px)');

  const handleSettingsClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setShowSettings(!showSettings);
  };

  const handleCloseSettingsModal = () => {
    setShowSettingsModal(false);
  };

  const handleOpenProfileModal = () => {
    setShowSettings(false);
    setShowProfileModal(true);
  };
  const handleCloseProfileModal = () => {
    setShowProfileModal(false);
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearchTerm(value);
    onSearchChange?.(value);
  };

  const handleClearSearch = () => {
    setSearchTerm("");
    onSearchChange?.("");
  };

  const renderIcon = () => {
    if (createButtonText === "Upload the app") {
      return (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
      );
    }
    return (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
      </svg>
    );
  };



  return (
    <div className="header-container">
      {/* Desktop: all in one row; Mobile: stacked */}
      {!isMobile ? (
      <div className="hidden md:flex items-center justify-between w-full gap-4">
        <div className="flex items-center gap-6 flex-1 min-w-0 justify-between">
          {titleContent ? titleContent : title && (
            <h2 className="header-title whitespace-nowrap">{title}</h2>
          )}
          {!hideSearch && (
            <div className="relative w-full max-w-xs ml-4">
              <input
                type="text"
                placeholder="Search..."
                value={searchTerm}
                onChange={handleSearchChange}
                className="header-search px-4 py-2 focus:outline-none focus:ring-2 focus:ring-theme-primary w-full"
              />
              {searchTerm && (
                <button
                  onClick={handleClearSearch}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-theme-primary hover:text-theme-primary-hover"
                  aria-label="Clear search"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-5 w-5"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                  >
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                      clipRule="evenodd"
                    />
                  </svg>
                </button>
              )}
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          {additionalButton}
          {/* DesktopCreateButton */}
          {createButtonText && (
            <button
              onClick={onCreateClick}
              className="header-action-btn hidden md:flex px-4 py-2 items-center"
            >
              {renderIcon()}
              <span className="ml-2">{createButtonText}</span>
            </button>
          )}
          <div className="relative">
            <button
              onClick={handleSettingsClick}
              className="header-settings-btn"
              aria-label="Settings"
            >
              <i className="fas fa-cog text-xl"></i>
            </button>
            {showSettings && <SettingsMenu onClose={() => {
              setShowSettings(false);
            }} onOpenProfileModal={handleOpenProfileModal} />}
          </div>
        </div>
      </div>
      ) : ( 
      <div className="flex flex-col md:hidden gap-2 mt-0">
        <div className="flex justify-between items-center">
          <button
            className="p-2 rounded-lg bg-theme-card shadow-lg focus:outline-none focus:ring-2 focus:ring-theme-focus hover:bg-theme-card-hover transition-colors duration-200"
            aria-label="Open menu"
            onClick={onMenuClick}
          >
            <svg className="w-7 h-7 text-theme-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <div className="flex items-center ml-auto">
            {additionalButton}
            {/* MobileCreateButton */}
            {createButtonText && (
              <button
                onClick={onCreateClick}
                className="header-action-btn md:hidden p-2.5 ml-2 flex items-center justify-center"
                aria-label={createButtonText}
              >
                {renderIcon()}
              </button>
            )}
            <div className="relative ml-2">
              <button
                onClick={handleSettingsClick}
                className="header-settings-btn"
                aria-label="Settings"
              >
                <i className="fas fa-cog text-xl"></i>
              </button>
              {showSettings && <SettingsMenu onClose={() => {
                setShowSettings(false);
              }} onOpenProfileModal={handleOpenProfileModal} />}
            </div>
          </div>
        </div>
        {titleContent ? (
          <div className="mb-2 min-w-0">{titleContent}</div>
        ) : title && (
          <h2 className="header-title mb-2">{title}</h2>
        )}
        {!hideSearch && (
          <div className="relative w-full">
            <input
              type="text"
              placeholder="Search..."
              value={searchTerm}
              onChange={handleSearchChange}
              className="header-search px-4 py-2 focus:outline-none focus:ring-2 focus:ring-theme-primary w-full"
            />
            {searchTerm && (
              <button
                onClick={handleClearSearch}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-theme-primary hover:text-theme-primary-hover"
                aria-label="Clear search"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-5 w-5"
                  viewBox="0 0 20 20"
                  fill="currentColor"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                    clipRule="evenodd"
                  />
                </svg>
              </button>
            )}
          </div>
        )}
      </div> 
      )}
      {showSettingsModal && <SettingsModal onClose={handleCloseSettingsModal} />}
      {showProfileModal && <ProfileModal onClose={handleCloseProfileModal} />}
    </div>
  );
}; 