import React, { useState, useEffect } from 'react';
import { useToast } from '@/hooks/useToast';
import { useUsersQuery } from '@/hooks/use-query/useUsersQuery';
import { StepStatus, TufHistoryEntry } from '@/components/settings/tuf/types';
import { getStatusColor, getStatusIcon } from '@/components/settings/tuf/utils';
import { generateTufKmsCommands } from '@/components/settings/tuf/generateTufKmsCommands';
import { Dropdown } from '@/components/common/Dropdown';
import { FIELD_INPUT, FIELD_LABEL } from '@/components/common/ui';

interface GenerateKeysOfflineProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  onGeneratedPayload: (payload: string) => void;
  onStartBootstrap: (payload: string) => void;
  onSaveToHistory: (entry: Omit<TufHistoryEntry, 'id'>) => void;
}

export const GenerateKeysOffline: React.FC<GenerateKeysOfflineProps> = ({
  selectedApp,
  isBootstrapSuccess,
  onGeneratedPayload: _onGeneratedPayload,
  onStartBootstrap: _onStartBootstrap,
  onSaveToHistory,
}) => {
  const [showStep1, setShowStep1] = useState(false);
  const [step1Status, setStep1Status] = useState<StepStatus>('ready');
  const [keyType, setKeyType] = useState<string>('ed25519');
  const [roleName, setRoleName] = useState<string>('default');
  const [metadataUrl, setMetadataUrl] = useState<string>('');

  // Served by the API as /dashboard/config.json, so the default works without rebuilding the dashboard
  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}config.json`)
      .then((res) => (res.ok ? res.json() : null))
      .then((config: { tufMetadataURL?: string } | null) => {
        const url = config?.tufMetadataURL;
        if (url) setMetadataUrl((current) => current || url);
      })
      .catch(() => {});
  }, []);
  const [expiration, setExpiration] = useState({
    root: 364,
    timestamp: 1,
    snapshot: 6,
    targets: 6,
  });
  const [thresholds, setThresholds] = useState({
    root: 2,
    timestamp: 1,
    snapshot: 1,
    targets: 1,
    delegation: 1,
  });
  const [generatedCommands, setGeneratedCommands] = useState<string>('');
  const [showCommands, setShowCommands] = useState(false);
  const { toastSuccess, toastError } = useToast();
  const { data: userData } = useUsersQuery();

  // Update step status when app changes
  useEffect(() => {
    if (!selectedApp) {
      setStep1Status('ready');
      setGeneratedCommands('');
    }
  }, [selectedApp]);

  const buildCommands = () => {
    const adminName = userData?.owner || userData?.username || 'admin';
    const commands = generateTufKmsCommands({
      appName: selectedApp,
      keyType,
      roleName,
      adminName,
      metadataUrl,
      expiration,
      thresholds,
    });

    setGeneratedCommands(commands);
    setShowCommands(true);
    setStep1Status('success');

    toastSuccess('Commands generated successfully!');

    onSaveToHistory({
      timestamp: new Date().toISOString(),
      appName: selectedApp,
      operation: 'generate',
      status: 'success',
    });
  };

  const handleGenerateCommands = () => {
    if (!selectedApp || !roleName) {
      toastError('Please fill in all required fields');
      return;
    }
    buildCommands();
  };

  const handleCopyCommands = async () => {
    if (generatedCommands) {
      try {
        await navigator.clipboard.writeText(generatedCommands);
        toastSuccess('Commands copied to clipboard successfully!');
      } catch (err) {
        console.error('Failed to copy commands:', err);
        toastError('Failed to copy commands');
      }
    }
  };

  if (!selectedApp || isBootstrapSuccess) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border-2 border-blue-500">
      <button
        onClick={() => setShowStep1(!showStep1)}
        className="flex items-center justify-between w-full text-theme-primary hover:text-theme-button-primary mb-4"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-bold">
            Step 1: Generate TUF Root Keys (Offline Mode)
          </h2>
          <div className={`flex items-center ${getStatusColor(step1Status)}`}>
            <i className={`fas ${getStatusIcon(step1Status)} mr-2`}></i>
            <span className="text-sm capitalize">{step1Status.replace('-', ' ')}</span>
          </div>
        </div>
        <i className={`fas fa-chevron-${showStep1 ? 'up' : 'down'}`}></i>
      </button>

      {showStep1 && (
        <>
          {/* Instructions */}
          <div className="mb-6 p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
            <div className="flex items-start">
              <i className="fas fa-info-circle text-blue-500 mr-3 mt-0.5 text-xl"></i>
              <div className="flex-1">
                <h3 className="text-blue-500 font-semibold mb-2">Offline Key Generation</h3>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  This is the recommended approach for generating TUF root keys. Configure the parameters below,
                  then generate the <code className="bg-theme-input px-1 rounded">tuf-kms</code> commands to run
                  offline on a secure machine.
                </p>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  <strong>Prerequisites:</strong>
                </p>
                <ul className="text-theme-primary text-sm leading-relaxed list-disc list-inside ml-2 space-y-1 mb-3">
                  <li>The <code className="bg-theme-input px-1 rounded">tuf-kms</code> binary on a secure offline machine.</li>
                </ul>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  <strong>Instructions:</strong>
                </p>
                <ol className="text-theme-primary text-sm leading-relaxed list-decimal list-inside ml-2 space-y-1 mb-3">
                  <li>Configure all parameters below</li>
                  <li>Click "Generate Commands"</li>
                  <li>Install <code className="bg-theme-input px-1 rounded">tuf-kms</code> on the offline machine (once), or download a binary from the releases page:</li>
                </ol>
                <div className="bg-theme-input rounded-lg p-3 mb-3 font-mono text-xs text-theme-primary overflow-x-auto">
                  <div className="whitespace-pre">go install github.com/ku9nov/tuf-kms@latest</div>
                </div>
                <ol className="text-theme-primary text-sm leading-relaxed list-decimal list-inside ml-2 space-y-1" start={4}>
                  <li>Run the generated commands in an empty working directory. <code className="bg-theme-input px-1 rounded">bootstrap generate</code> asks for a passphrase — it encrypts the root private keys. Store it as carefully as the keys themselves; rotation is impossible without it.</li>
                  <li>Copy <code className="bg-theme-input px-1 rounded">out/online-keys/*</code> to the <code className="bg-theme-input px-1 rounded">ONLINE_KEY_DIR</code> folder specified in the environment variables of the faynosync API server. It holds only the targets, snapshot, timestamp and delegated keys. The root private keys stay in <code className="bg-theme-input px-1 rounded">keys/root/</code>, encrypted, and must never reach the server.</li>
                  <li>Use the generated <code className="bg-theme-input px-1 rounded">out/bootstrap-payload.json</code> to proceed with bootstrap</li>
                  <li>Keep the working directory (<code className="bg-theme-input px-1 rounded">tuf-kms.yaml</code>, <code className="bg-theme-input px-1 rounded">keystore.json</code>, <code className="bg-theme-input px-1 rounded">keys/</code>, <code className="bg-theme-input px-1 rounded">trust/</code>) offline and backed up — every later rotation reads it.</li>
                </ol>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className={FIELD_LABEL}>App Name</label>
              <input
                type="text"
                value={selectedApp}
                disabled
                className={`${FIELD_INPUT} disabled:opacity-50`}
              />
            </div>

            <div>
              <label className={FIELD_LABEL}>Key Type</label>
              <Dropdown
                ariaLabel="Key type"
                value={keyType}
                onChange={setKeyType}
                options={['ed25519', 'rsa', 'ecdsa'].map((type) => ({ value: type, label: type }))}
              />
            </div>

            <div>
              <label className={FIELD_LABEL}>Role Name</label>
              <input
                type="text"
                value={roleName}
                onChange={(e) => setRoleName(e.target.value)}
                placeholder="Enter role name (e.g., root, timestamp, snapshot, targets)"
                className={FIELD_INPUT}
              />
            </div>

            <div>
              <label className={FIELD_LABEL}>Public Metadata URL (optional)</label>
              <input
                type="text"
                value={metadataUrl}
                onChange={(e) => setMetadataUrl(e.target.value)}
                placeholder="https://s3.example.com/tuf_metadata"
                className={FIELD_INPUT}
              />
              <p className="text-xs text-theme-secondary mt-1">
                Not used by bootstrap. Set it now and later key rotations work without editing tuf-kms.yaml by hand.
              </p>
            </div>

            <div>
              <label className={FIELD_LABEL}>Keys Threshold</label>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Root</label>
                  <input
                    type="number"
                    min={1}
                    value={thresholds.root}
                    onChange={(e) => setThresholds(prev => ({ ...prev, root: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Targets</label>
                  <input
                    type="number"
                    min={1}
                    value={thresholds.targets}
                    onChange={(e) => setThresholds(prev => ({ ...prev, targets: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Timestamp</label>
                  <input
                    type="number"
                    min={1}
                    value={thresholds.timestamp}
                    onChange={(e) => setThresholds(prev => ({ ...prev, timestamp: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Snapshot</label>
                  <input
                    type="number"
                    min={1}
                    value={thresholds.snapshot}
                    onChange={(e) => setThresholds(prev => ({ ...prev, snapshot: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Delegation</label>
                  <input
                    type="number"
                    min={1}
                    value={thresholds.delegation}
                    onChange={(e) => setThresholds(prev => ({ ...prev, delegation: Math.max(1, parseInt(e.target.value) || 1) }))}
                    className={FIELD_INPUT}
                  />
                </div>
              </div>
            </div>

            <div>
              <label className={FIELD_LABEL}>Expiration Settings</label>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Root (days)</label>
                  <input
                    type="number"
                    value={expiration.root}
                    onChange={(e) => setExpiration(prev => ({ ...prev, root: parseInt(e.target.value) || 0 }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Timestamp (days)</label>
                  <input
                    type="number"
                    value={expiration.timestamp}
                    onChange={(e) => setExpiration(prev => ({ ...prev, timestamp: parseInt(e.target.value) || 0 }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Snapshot (days)</label>
                  <input
                    type="number"
                    value={expiration.snapshot}
                    onChange={(e) => setExpiration(prev => ({ ...prev, snapshot: parseInt(e.target.value) || 0 }))}
                    className={FIELD_INPUT}
                  />
                </div>
                <div>
                  <label className="block text-sm text-theme-primary mb-1">Targets (days)</label>
                  <input
                    type="number"
                    value={expiration.targets}
                    onChange={(e) => setExpiration(prev => ({ ...prev, targets: parseInt(e.target.value) || 0 }))}
                    className={FIELD_INPUT}
                  />
                </div>
              </div>
            </div>

            <div className="flex gap-2 items-center">
              <button
                onClick={handleGenerateCommands}
                disabled={!selectedApp || !roleName}
                className="bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <i className="fas fa-terminal mr-2"></i>
                Generate Commands
              </button>
              {generatedCommands && (
                <button
                  onClick={handleCopyCommands}
                  className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors"
                >
                  <i className="fas fa-copy mr-2"></i>
                  Copy Commands
                </button>
              )}
            </div>

            {generatedCommands && (
              <div className="mt-4">
                <button
                  onClick={() => setShowCommands(!showCommands)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showCommands ? 'up' : 'down'} mr-2`}></i>
                  Generated Commands {showCommands ? '(click to hide)' : '(click to expand)'}
                </button>
                {showCommands && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {generatedCommands}
                    </pre>
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={handleCopyCommands}
                        className="bg-theme-button-primary text-theme-primary px-3 py-1 rounded text-sm hover:bg-theme-button-primary-hover"
                      >
                        <i className="fas fa-copy mr-1"></i>
                        Copy Commands
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
