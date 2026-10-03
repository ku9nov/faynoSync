import React from 'react';
import { Platform } from '@/hooks/use-query/usePlatformQuery';

interface PlatformCardProps {
  platform: Platform;
  onClick: () => void;
  onDelete?: () => void;
}

export const PlatformCard: React.FC<PlatformCardProps> = ({ 
  platform, 
  onClick,
  onDelete,
}) => {
  const handleDeleteClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onDelete) {
      onDelete();
    }
  };

  const defaultUpdater = platform.Updaters?.find(u => u.default);
  const updatersCount = platform.Updaters?.length || 0;

  return (
    <div
      className={"sharedCard sharedCard--compact bg-theme-card backdrop-blur-lg rounded-lg p-2 text-theme-primary hover:bg-theme-card-hover transition-colors cursor-pointer flex items-center"}
      style={{ ['--card-color' as any]: '#8B5CF6' }}
      onClick={onClick}
    >
      <div className="flex items-center min-w-0 w-full">
        <div className="flex-1 min-w-0">
          <h3
            className="sharedCardTitle text-xl font-semibold truncate max-w-[200px] overflow-hidden"
            title={platform.PlatformName}
          >
            {platform.PlatformName}
          </h3>
          {updatersCount > 0 && (
            <div className="flex items-center space-x-2 mt-1">
              <span className="text-xs text-theme-secondary">
                {updatersCount} updater{updatersCount !== 1 ? 's' : ''}
              </span>
              {defaultUpdater && (
                <span className="text-xs bg-purple-600 text-white px-2 py-1 rounded-full">
                  Default: {defaultUpdater.type}
                </span>
              )}
            </div>
          )}
        </div>
        <button
          onClick={handleDeleteClick}
          className="p-2 text-theme-danger hover:text-theme-primary-hover transition-colors duration-200 ml-2"
          title="Delete platform"
        >
          <i className="fas fa-trash"></i>
        </button>
      </div>
    </div>
  );
}; 