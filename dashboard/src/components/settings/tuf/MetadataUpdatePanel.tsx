import React, { useState } from 'react';

interface MetadataUpdatePanelProps {
  onUpdateMetadata: (roles: string[]) => Promise<void> | void;
  title?: string;
  description?: string;
}

export const MetadataUpdatePanel: React.FC<MetadataUpdatePanelProps> = ({
  onUpdateMetadata,
  title = 'Update Metadata Files',
  description = 'After updating the configuration, you need to update the metadata files to apply the changes. Select which roles to update, or leave all unchecked to update all roles (timestamp, targets, snapshot).',
}) => {
  const [selectedRoles, setSelectedRoles] = useState<{
    timestamp: boolean;
    targets: boolean;
    snapshot: boolean;
  }>({
    timestamp: false,
    targets: false,
    snapshot: false,
  });
  const [customRole, setCustomRole] = useState<string>('');
  const [updatingMetadata, setUpdatingMetadata] = useState(false);

  const handleRoleToggle = (role: 'timestamp' | 'targets' | 'snapshot') => {
    setSelectedRoles((prev) => ({
      ...prev,
      [role]: !prev[role],
    }));
  };

  const handleUpdateAllRoles = () => {
    setSelectedRoles({
      timestamp: true,
      targets: true,
      snapshot: true,
    });
  };

  const handleClearAllRoles = () => {
    setSelectedRoles({
      timestamp: false,
      targets: false,
      snapshot: false,
    });
    setCustomRole('');
  };

  const handleUpdateMetadata = async () => {
    const roles: string[] = [];
    if (selectedRoles.timestamp) roles.push('timestamp');
    if (selectedRoles.targets) roles.push('targets');
    if (selectedRoles.snapshot) roles.push('snapshot');
    if (customRole.trim()) roles.push(customRole.trim());

    setUpdatingMetadata(true);
    try {
      await onUpdateMetadata(roles);
      setSelectedRoles({
        timestamp: false,
        targets: false,
        snapshot: false,
      });
      setCustomRole('');
    } finally {
      setUpdatingMetadata(false);
    }
  };

  return (
    <div className="mt-6 p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
      <div className="flex items-start mb-4">
        <i className="fas fa-info-circle text-blue-500 mr-3 mt-0.5 text-xl"></i>
        <div className="flex-1">
          <h3 className="text-blue-500 font-semibold mb-2">{title}</h3>
          <p className="text-theme-primary text-sm leading-relaxed mb-3">{description}</p>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-semibold text-theme-primary mb-3">
            Select Roles to Update
          </label>
          <div className="flex flex-wrap gap-4 mb-3">
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={selectedRoles.timestamp}
                onChange={() => handleRoleToggle('timestamp')}
                className="mr-2 w-4 h-4 text-blue-500 rounded focus:ring-blue-500"
              />
              <span className="text-theme-primary">Timestamp</span>
            </label>
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={selectedRoles.targets}
                onChange={() => handleRoleToggle('targets')}
                className="mr-2 w-4 h-4 text-blue-500 rounded focus:ring-blue-500"
              />
              <span className="text-theme-primary">Targets</span>
            </label>
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={selectedRoles.snapshot}
                onChange={() => handleRoleToggle('snapshot')}
                className="mr-2 w-4 h-4 text-blue-500 rounded focus:ring-blue-500"
              />
              <span className="text-theme-primary">Snapshot</span>
            </label>
          </div>
          <div className="flex gap-2 mb-3">
            <button
              onClick={handleUpdateAllRoles}
              className="text-xs text-blue-500 hover:text-blue-600"
            >
              Select All
            </button>
            <span className="text-theme-primary opacity-50">|</span>
            <button
              onClick={handleClearAllRoles}
              className="text-xs text-blue-500 hover:text-blue-600"
            >
              Clear All
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm text-theme-primary mb-2">
            Custom Role (optional)
          </label>
          <input
            type="text"
            value={customRole}
            onChange={(e) => setCustomRole(e.target.value)}
            placeholder="Enter custom role name..."
            className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2 text-sm"
          />
          <p className="text-xs text-theme-primary opacity-70 mt-1">
            You can specify a custom role name to update
          </p>
        </div>

        <div className="flex justify-end gap-2">
          <button
            onClick={handleUpdateMetadata}
            disabled={updatingMetadata}
            className="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {updatingMetadata ? (
              <>
                <i className="fas fa-spinner fa-spin mr-2"></i>
                Updating...
              </>
            ) : (
              <>
                <i className="fas fa-sync mr-2"></i>
                Update Metadata
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
