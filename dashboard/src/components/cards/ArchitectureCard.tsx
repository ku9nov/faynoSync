import React from 'react';

interface ArchitectureCardProps {
  archName: string;
  onClick: () => void;
  onDelete?: () => void;
}

export const ArchitectureCard: React.FC<ArchitectureCardProps> = ({
  archName,
  onClick,
  onDelete,
}) => {
  const handleDeleteClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onDelete) {
      onDelete();
    }
  };

  return (
    <div
      className={"sharedCard sharedCard--compact bg-theme-card backdrop-blur-lg rounded-lg p-2 text-theme-primary hover:bg-theme-card-hover transition-colors cursor-pointer flex items-center"}
      style={{ ['--card-color' as any]: '#8B5CF6' }}
      onClick={onClick}
    >
      <div className="flex items-center min-w-0 w-full">
        <h2
          className="sharedCardTitle text-xl font-semibold truncate max-w-[200px] overflow-hidden"
          title={archName}
        >
          {archName}
        </h2>
        <button
          onClick={handleDeleteClick}
          className="p-2 text-theme-danger hover:text-theme-primary-hover transition-colors duration-200 ml-auto"
          title="Delete architecture"
        >
          <i className="fas fa-trash"></i>
        </button>
      </div>
    </div>
  );
};
