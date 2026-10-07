import React, { useState } from 'react';
import { TufConfig } from '@/components/settings/tuf/types';
import { MetadataUpdatePanel } from '@/components/settings/tuf/MetadataUpdatePanel';

interface ConfigProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  tufConfig: TufConfig | null;
  configLoading: boolean;
  configUpdating: boolean;
  editableExpiration: {
    targets: number;
    snapshot: number;
    timestamp: number;
  };
  onLoadConfig: () => void;
  onUpdateConfig: (expiration: { targets: number; snapshot: number; timestamp: number }) => void;
  onResetConfigLoaded: () => void;
  onUpdateMetadata: (roles: string[]) => Promise<void> | void;
}

export const Config: React.FC<ConfigProps> = ({
  selectedApp,
  isBootstrapSuccess,
  tufConfig,
  configLoading,
  configUpdating,
  editableExpiration,
  onLoadConfig,
  onUpdateConfig,
  onResetConfigLoaded,
  onUpdateMetadata,
}) => {
  const [showConfig, setShowConfig] = useState(false);
  const [localExpiration, setLocalExpiration] = useState(editableExpiration);

  React.useEffect(() => {
    setLocalExpiration(editableExpiration);
  }, [editableExpiration]);

  const handleRefresh = () => {
    onResetConfigLoaded();
    onLoadConfig();
  };

  const handleUpdateConfig = () => {
    onUpdateConfig(localExpiration);
  };

  if (!selectedApp || !isBootstrapSuccess) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
      <div className="flex items-center justify-between mb-4">
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="flex items-center gap-3 text-theme-primary hover:text-theme-button-primary transition-colors"
        >
          <h2 className="text-lg font-bold">
            Update tuf config
          </h2>
          <i className={`fas fa-chevron-${showConfig ? 'up' : 'down'}`}></i>
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            handleRefresh();
          }}
          disabled={configLoading}
          className="text-theme-primary hover:text-theme-button-primary transition-colors disabled:opacity-50"
          title="Reload config"
        >
          <i className={`fas fa-sync ${configLoading ? 'fa-spin' : ''} mr-2`}></i>
          Refresh
        </button>
      </div>

      {showConfig && (
        <>
          {configLoading ? (
            <div className="text-center py-8">
              <i className="fas fa-spinner fa-spin text-theme-primary text-2xl mb-2"></i>
              <p className="text-theme-primary opacity-70">Loading config...</p>
            </div>
          ) : tufConfig ? (
            <div className="space-y-6">
              {/* Read-only fields */}
              <div>
                <h3 className="text-md font-semibold text-theme-primary mb-3">Configuration Details</h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Bootstrap ID</div>
                    <div className="text-theme-primary font-mono text-sm">{tufConfig.bootstrap}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Role Expiration</div>
                    <div className="text-theme-primary">{tufConfig.role_expiration} days</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Root Expiration</div>
                    <div className="text-theme-primary">{tufConfig.root_expiration} days</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Root Keys</div>
                    <div className="text-theme-primary">{tufConfig.root_num_keys}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Root Threshold</div>
                    <div className="text-theme-primary">{tufConfig.root_threshold}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Snapshot Keys</div>
                    <div className="text-theme-primary">{tufConfig.snapshot_num_keys}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Snapshot Threshold</div>
                    <div className="text-theme-primary">{tufConfig.snapshot_threshold}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Targets Keys</div>
                    <div className="text-theme-primary">{tufConfig.targets_num_keys}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Targets Online Key</div>
                    <div className="text-theme-primary">{tufConfig.targets_online_key}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Targets Threshold</div>
                    <div className="text-theme-primary">{tufConfig.targets_threshold}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Timestamp Keys</div>
                    <div className="text-theme-primary">{tufConfig.timestamp_num_keys}</div>
                  </div>
                  <div className="bg-theme-input p-3 rounded-lg border border-theme">
                    <div className="text-sm text-theme-primary opacity-70 mb-1">Timestamp Threshold</div>
                    <div className="text-theme-primary">{tufConfig.timestamp_threshold}</div>
                  </div>
                </div>
              </div>

              {/* Editable expiration fields */}
              <div>
                <h3 className="text-md font-semibold text-theme-primary mb-3">Expiration Settings (Editable)</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-theme-input p-4 rounded-lg border border-theme">
                    <label className="block text-sm text-theme-primary mb-2">
                      Targets Expiration (days)
                    </label>
                    <input
                      type="number"
                      value={localExpiration.targets}
                      onChange={(e) => setLocalExpiration(prev => ({ ...prev, targets: parseInt(e.target.value) || 0 }))}
                      className="w-full bg-theme-card text-theme-primary border border-theme rounded-lg px-4 py-2"
                      min="1"
                    />
                    <p className="text-xs text-theme-primary opacity-70 mt-1">
                      Current: {tufConfig.targets_expiration} days
                    </p>
                  </div>
                  <div className="bg-theme-input p-4 rounded-lg border border-theme">
                    <label className="block text-sm text-theme-primary mb-2">
                      Snapshot Expiration (days)
                    </label>
                    <input
                      type="number"
                      value={localExpiration.snapshot}
                      onChange={(e) => setLocalExpiration(prev => ({ ...prev, snapshot: parseInt(e.target.value) || 0 }))}
                      className="w-full bg-theme-card text-theme-primary border border-theme rounded-lg px-4 py-2"
                      min="1"
                    />
                    <p className="text-xs text-theme-primary opacity-70 mt-1">
                      Current: {tufConfig.snapshot_expiration} days
                    </p>
                  </div>
                  <div className="bg-theme-input p-4 rounded-lg border border-theme">
                    <label className="block text-sm text-theme-primary mb-2">
                      Timestamp Expiration (days)
                    </label>
                    <input
                      type="number"
                      value={localExpiration.timestamp}
                      onChange={(e) => setLocalExpiration(prev => ({ ...prev, timestamp: parseInt(e.target.value) || 0 }))}
                      className="w-full bg-theme-card text-theme-primary border border-theme rounded-lg px-4 py-2"
                      min="1"
                    />
                    <p className="text-xs text-theme-primary opacity-70 mt-1">
                      Current: {tufConfig.timestamp_expiration} days
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleUpdateConfig}
                  disabled={configUpdating}
                  className="bg-theme-button-primary text-theme-primary px-6 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {configUpdating ? (
                    <>
                      <i className="fas fa-spinner fa-spin mr-2"></i>
                      Updating...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-save mr-2"></i>
                      Update Config
                    </>
                  )}
                </button>
              </div>

              {/* Metadata Update Section */}
              {tufConfig && (
                <MetadataUpdatePanel onUpdateMetadata={onUpdateMetadata} />
              )}
            </div>
          ) : (
            <div className="text-center py-8">
              <p className="text-theme-primary opacity-70">No config available</p>
            </div>
          )}
        </>
      )}
    </div>
  );
};
