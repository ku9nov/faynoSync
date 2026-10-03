import React, { useEffect, useState } from 'react';
import axiosInstance from '@/config/axios';
import { useToast } from '@/hooks/useToast';
import { deleteSigningMetadata } from '@/components/settings/tuf/deleteSigningMetadata';
import { MetadataUpdatePanel } from '@/components/settings/tuf/MetadataUpdatePanel';
import { Dropdown } from '@/components/common/Dropdown';

interface RotateRoleKeysProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  onSaveToHistory: (entry: Omit<import('@/components/settings/tuf/types').TufHistoryEntry, 'id'>) => void;
  onCheckTufTasks: (taskId?: string) => void;
  onUpdateMetadata: (roles: string[]) => Promise<void> | void;
}

type BuiltInRole = 'timestamp' | 'snapshot' | 'targets';

const isThresholdNotMetError = (message: string): boolean => {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('threshold not reached') ||
    normalized.includes('not enough signatures') ||
    normalized.includes('new root not signed by trusted root') ||
    normalized.includes('progress:')
  );
};

const normalizeTrustedRootMetadata = (value: unknown): any | null => {
  if (!value) {
    return null;
  }

  if (typeof value === 'string') {
    try {
      return normalizeTrustedRootMetadata(JSON.parse(value));
    } catch {
      return null;
    }
  }

  if (typeof value !== 'object') {
    return null;
  }

  const candidate = value as Record<string, any>;

  if (candidate.signed?.keys && candidate.signed?.roles) {
    return candidate;
  }

  if (candidate.data?.trusted_root) {
    return normalizeTrustedRootMetadata(candidate.data.trusted_root);
  }

  if (candidate.trusted_root) {
    return normalizeTrustedRootMetadata(candidate.trusted_root);
  }

  return null;
};

export const RotateRoleKeys: React.FC<RotateRoleKeysProps> = ({
  selectedApp,
  isBootstrapSuccess,
  onSaveToHistory,
  onCheckTufTasks,
  onUpdateMetadata,
}) => {
  const { toastSuccess, toastError } = useToast();

  const [showRotateRoleKeys, setShowRotateRoleKeys] = useState(false);
  const [selectedRole, setSelectedRole] = useState<BuiltInRole>('timestamp');
  const [keyCount, setKeyCount] = useState(1);
  const [threshold, setThreshold] = useState(1);
  const [expirationDays, setExpirationDays] = useState(0);

  const [rootMetadata, setRootMetadata] = useState<any>(null);
  const [rootMetadataAppName, setRootMetadataAppName] = useState<string | null>(null);
  const [showRootMetadataStep1, setShowRootMetadataStep1] = useState(false);
  const [showRootMetadataStep4, setShowRootMetadataStep4] = useState(false);
  const [loadingRootMetadata, setLoadingRootMetadata] = useState(false);

  const [metadataPayload, setMetadataPayload] = useState('');
  const [metadataPayloadError, setMetadataPayloadError] = useState('');
  const [submittingMetadata, setSubmittingMetadata] = useState(false);

  const [signaturePayload, setSignaturePayload] = useState('');
  const [signaturePayloadError, setSignaturePayloadError] = useState('');
  const [submittingSignature, setSubmittingSignature] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState<string>('');
  const [signatureErrorMessage, setSignatureErrorMessage] = useState('');

  const [checkingMetadataStatus, setCheckingMetadataStatus] = useState(false);
  const [metadataStatusResult, setMetadataStatusResult] = useState<string | null>(null);
  const [deletingSigningMetadata, setDeletingSigningMetadata] = useState(false);

  // 0 means "leave root's expiry where it is": tuf-kms keeps the current one
  // when the flag is absent, and a rotation of an online role has no reason to
  // move it by default.
  const rotateCommand = [
    `tuf-kms rotate role ${selectedRole}`,
    `  --keys ${keyCount}`,
    `  --threshold ${threshold}`,
    ...(expirationDays > 0 ? [`  --root-expires ${expirationDays}`] : []),
  ].join(' \\\n');

  useEffect(() => {
    setRootMetadata(null);
    setRootMetadataAppName(null);
  }, [selectedApp]);

  useEffect(() => {
    if (threshold > keyCount) {
      setThreshold(keyCount);
    }
  }, [keyCount, threshold]);

  const fetchCurrentRootMetadata = async (showSuccessToast: boolean): Promise<boolean> => {
    if (!selectedApp) {
      return false;
    }
    setLoadingRootMetadata(true);
    try {
      const response = await axiosInstance.get(`/tuf/v1/metadata/root?appName=${encodeURIComponent(selectedApp)}`);
      const responseData = response.data?.data;
      if (!responseData || !responseData.trusted_root) {
        throw new Error('Invalid response: missing trusted_root field');
      }

      const normalizedRoot = normalizeTrustedRootMetadata(responseData.trusted_root);
      if (!normalizedRoot) {
        throw new Error('Invalid trusted_root format');
      }

      setRootMetadata(normalizedRoot);
      setRootMetadataAppName(selectedApp);
      if (showSuccessToast) {
        toastSuccess('Root metadata loaded successfully!');
      }
      return true;
    } catch (error: any) {
      console.error('Failed to get root metadata:', error);
      if (showSuccessToast) {
        const errorMessage = error.response?.data?.message || error.message || 'Failed to get root metadata';
        toastError(errorMessage);
      }
      setRootMetadata(null);
      setRootMetadataAppName(null);
      return false;
    } finally {
      setLoadingRootMetadata(false);
    }
  };

  useEffect(() => {
    if (!showRotateRoleKeys || !selectedApp || !isBootstrapSuccess || loadingRootMetadata) {
      return;
    }
    if (rootMetadata && rootMetadataAppName === selectedApp) {
      return;
    }
    void fetchCurrentRootMetadata(false);
  }, [
    showRotateRoleKeys,
    selectedApp,
    isBootstrapSuccess,
    loadingRootMetadata,
    rootMetadata,
    rootMetadataAppName,
  ]);

  const handleCopyToClipboard = async (value: string, successMessage: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toastSuccess(successMessage);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      toastError('Failed to copy');
    }
  };

  const handleGetCurrentRoot = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    await fetchCurrentRootMetadata(true);
  };

  const handleCopyRootMetadata = async () => {
    if (!rootMetadata) {
      return;
    }
    await handleCopyToClipboard(JSON.stringify(rootMetadata, null, 2), 'Root metadata copied to clipboard successfully!');
  };

  const handleSubmitMetadata = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    if (!metadataPayload.trim()) {
      setMetadataPayloadError('Metadata payload is required');
      return;
    }

    let parsedMetadata;
    try {
      parsedMetadata = JSON.parse(metadataPayload);
      setMetadataPayloadError('');
    } catch {
      setMetadataPayloadError('Invalid JSON format');
      return;
    }

    setSubmittingMetadata(true);
    try {
      const response = await axiosInstance.post(
        `/tuf/v1/metadata?appName=${encodeURIComponent(selectedApp)}`,
        {
          metadata: {
            root: parsedMetadata,
          },
        }
      );
      const responseData = response.data?.data;
      if (!responseData?.task_id) {
        throw new Error('Invalid response: missing task_id');
      }

      toastSuccess('Metadata submitted successfully!');
      setMetadataPayload('');

      onSaveToHistory({
        timestamp: responseData.last_update || new Date().toISOString(),
        appName: selectedApp,
        operation: 'root-meta-update',
        status: 'pending',
        taskId: responseData.task_id,
      });
      setTimeout(() => onCheckTufTasks(responseData.task_id), 1000);
    } catch (error: any) {
      console.error('Failed to submit metadata:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to submit metadata';
      toastError(errorMessage);
      onSaveToHistory({
        timestamp: new Date().toISOString(),
        appName: selectedApp,
        operation: 'root-meta-update',
        status: 'failed',
      });
    } finally {
      setSubmittingMetadata(false);
    }
  };

  const handleSubmitSignature = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    if (!signaturePayload.trim()) {
      setSignaturePayloadError('Signature payload is required');
      return;
    }

    let parsedSignature;
    try {
      parsedSignature = JSON.parse(signaturePayload);
      if (!parsedSignature.keyid || !parsedSignature.sig) {
        setSignaturePayloadError('Signature must contain keyid and sig fields');
        return;
      }
      setSignaturePayloadError('');
    } catch {
      setSignaturePayloadError('Invalid JSON format');
      return;
    }

    setSubmittingSignature(true);
    setSignatureStatus('');
    setSignatureErrorMessage('');

    try {
      const response = await axiosInstance.post(
        `/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`,
        {
          role: 'root',
          signature: parsedSignature,
        }
      );
      const message = response.data?.message || response.data?.data?.message || '';
      if (
        message === 'Metadata update finished' ||
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        toastSuccess('Metadata update finished! Role keys rotation completed successfully.');
      } else {
        setSignatureStatus('partial');
        toastSuccess(message || 'Signature submitted successfully. Continue submitting signatures.');
      }
      setSignaturePayload('');
    } catch (error: any) {
      const errorDetail = error.response?.data?.error || '';
      const errorMessage = error.response?.data?.message || '';
      const fullErrorMessage = errorDetail || errorMessage || error.message || 'Failed to submit signature';

      if (
        fullErrorMessage === 'No metadata pending signing available' ||
        fullErrorMessage.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        toastSuccess('Metadata update finished! Role keys rotation completed successfully.');
        setSignaturePayload('');
      } else if (isThresholdNotMetError(fullErrorMessage)) {
        setSignatureStatus('threshold');
        setSignatureErrorMessage('Threshold not met');
        toastError('Threshold not met');
        setSignaturePayload('');
      } else {
        setSignatureStatus('error');
        setSignatureErrorMessage(fullErrorMessage);
        toastError(fullErrorMessage);
      }
    } finally {
      setSubmittingSignature(false);
    }
  };

  const handleCheckMetadataStatus = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    setCheckingMetadataStatus(true);
    setMetadataStatusResult(null);
    try {
      const response = await axiosInstance.get(`/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`);
      const message = response.data?.message || response.data?.data?.message || '';

      if (
        message === 'Metadata update finished' ||
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setMetadataStatusResult('finished');
        toastSuccess('Metadata update finished! Role keys rotation completed successfully.');
      } else if (message) {
        setMetadataStatusResult('in-progress');
        toastSuccess(`Status: ${message}`);
      } else {
        setMetadataStatusResult('unknown');
        toastSuccess('Status checked successfully');
      }
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.response?.data?.error || error.message || 'Failed to check metadata status';
      if (errorMessage.includes('not enough signatures') || errorMessage.includes('threshold not reached')) {
        setMetadataStatusResult('threshold-not-met');
      } else {
        setMetadataStatusResult('error');
      }
      toastError(errorMessage);
    } finally {
      setCheckingMetadataStatus(false);
    }
  };

  const handleDeleteSigningMetadata = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    setDeletingSigningMetadata(true);
    try {
      const result = await deleteSigningMetadata({
        appName: selectedApp,
        role: 'root',
      });
      if (result.hasTask && result.taskId) {
        onSaveToHistory({
          timestamp: result.lastUpdate || new Date().toISOString(),
          appName: selectedApp,
          operation: 'metadata-update',
          status: 'pending',
          taskId: result.taskId,
        });
        setTimeout(() => onCheckTufTasks(result.taskId), 1000);
      }
      toastSuccess(result.message || 'Signing metadata deleted successfully.');
      setSignatureStatus('');
      setSignatureErrorMessage('');
      setSignaturePayload('');
    } catch (error: any) {
      toastError(error.message || 'Failed to delete signing metadata');
    } finally {
      setDeletingSigningMetadata(false);
    }
  };

  if (!selectedApp || !isBootstrapSuccess) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
      <button
        onClick={() => setShowRotateRoleKeys(!showRotateRoleKeys)}
        className="flex items-center justify-between w-full text-left text-theme-primary hover:text-theme-button-primary transition-colors"
      >
        <h2 className="text-lg font-bold">Rotate Top-Level Role Keys</h2>
        <i className={`fas fa-chevron-${showRotateRoleKeys ? 'up' : 'down'}`}></i>
      </button>

      {showRotateRoleKeys && (
        <div className="mt-6 space-y-6">
          <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
            <p className="text-theme-primary text-sm leading-relaxed mb-2">
              This flow rotates role keys for <code className="bg-theme-input px-1 rounded">timestamp</code>,
              <code className="bg-theme-input px-1 rounded ml-1">snapshot</code>,
              <code className="bg-theme-input px-1 rounded ml-1">targets</code> without root key rotation.
              Root trust remains anchored in root metadata signatures.
            </p>
            <p className="text-theme-primary text-sm leading-relaxed">
              These are online keys: the server holds them and signs with them. The new keys are generated on your
              offline machine and copied to <code className="bg-theme-input px-1 rounded">ONLINE_KEY_DIR</code>, while the
              root keys that authorise the change never leave it.
            </p>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 1: Rotate role keys</h2>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-theme-primary mb-2">Role</label>
                <Dropdown
                  ariaLabel="Role"
                  value={selectedRole}
                  onChange={(value) => setSelectedRole(value as BuiltInRole)}
                  options={['timestamp', 'snapshot', 'targets'].map((role) => ({ value: role, label: role }))}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-theme-primary mb-2">Number of keys</label>
                <input
                  type="number"
                  min={1}
                  value={keyCount}
                  onChange={(e) => setKeyCount(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                />
              </div>
              <div>
                <label className="block text-theme-primary mb-2">Role threshold</label>
                <input
                  type="number"
                  min={1}
                  max={keyCount}
                  value={threshold}
                  onChange={(e) => setThreshold(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                />
              </div>
              <div>
                <label className="block text-theme-primary mb-2">Root expiration (days)</label>
                <input
                  type="number"
                  min={0}
                  value={expirationDays}
                  onChange={(e) => setExpirationDays(Math.max(0, parseInt(e.target.value, 10) || 0))}
                  className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                />
                <p className="text-xs text-theme-primary opacity-70 mt-1">
                  0 keeps root's current expiry. Any other number is the new lifetime of the <strong>root</strong> metadata
                  this rotation produces — not of {selectedRole}.
                </p>
              </div>
            </div>

            <div>
              <label className="block text-theme-primary mb-2">Run on the offline machine</label>
              <div className="bg-theme-input rounded-lg p-4 border border-theme">
                <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">{rotateCommand}</pre>
                <div className="mt-2 flex gap-2">
                  <button
                    onClick={() => handleCopyToClipboard(rotateCommand, 'Command copied to clipboard successfully!')}
                    className="bg-theme-button-primary text-theme-primary px-3 py-1 rounded text-sm hover:bg-theme-button-primary-hover"
                  >
                    <i className="fas fa-copy mr-1"></i>
                    Copy Command
                  </button>
                </div>
              </div>
            </div>

            <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
              <div className="flex items-start">
                <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
                <div className="flex-1">
                  <p className="text-theme-primary text-sm leading-relaxed mb-2">
                    Rotating an online role rewrites root metadata, so the command asks for the root passphrase and signs
                    with the root keys. It writes:
                  </p>
                  <ul className="text-theme-primary text-sm leading-relaxed list-disc list-inside ml-2 space-y-1 mb-3">
                    <li><code className="bg-theme-input px-1 rounded">out/online-keys/</code> — the new {selectedRole} keys, for Step 2</li>
                    <li><code className="bg-theme-input px-1 rounded">out/root-metadata.json</code> — the new root metadata, for Step 3</li>
                    <li><code className="bg-theme-input px-1 rounded">out/signatures/root-old-*.json</code> — the root signatures, for Step 4</li>
                  </ul>
                  <p className="text-theme-primary text-sm leading-relaxed mb-2">
                    New keys use the key type stored in <code className="bg-theme-input px-1 rounded">tuf-kms.yaml</code>. The expiration is
                    the lifetime of the root metadata this rotation produces, counted from the moment the command runs —
                    which is why the flag is called <code className="bg-theme-input px-1 rounded">--root-expires</code>.
                  </p>
                  <p className="text-theme-primary text-sm leading-relaxed mb-2">
                    It cannot set {selectedRole}'s own lifetime: the server recomputes that from its own settings every time
                    it re-signs, so any value put in the metadata here would last until the next artifact is published.
                    Change it under <strong>TUF &rarr; Config</strong> instead.
                  </p>
                  <p className="text-theme-primary text-sm leading-relaxed">
                    <strong>Air-gapped machine:</strong> run <code className="bg-theme-input px-1 rounded">tuf-kms fetch</code> where there is
                    network, carry <code className="bg-theme-input px-1 rounded">trust/</code> over, and add <code className="bg-theme-input px-1 rounded">--trust-dir /media/usb/trust</code>.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-2 items-center">
              <button
                onClick={handleGetCurrentRoot}
                disabled={!selectedApp || loadingRootMetadata}
                className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingRootMetadata ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Loading...
                  </>
                ) : (
                  <>
                    <i className="fas fa-download mr-2"></i>
                    Get current root
                  </>
                )}
              </button>
              {rootMetadata && (
                <button
                  onClick={handleCopyRootMetadata}
                  className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors"
                >
                  <i className="fas fa-copy mr-2"></i>
                  Copy Root Metadata
                </button>
              )}
            </div>
            {rootMetadata && (
              <div>
                <button
                  onClick={() => setShowRootMetadataStep1(!showRootMetadataStep1)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showRootMetadataStep1 ? 'up' : 'down'} mr-2`}></i>
                  Current Root Metadata {showRootMetadataStep1 ? '(click to hide)' : '(click to expand)'}
                </button>
                {showRootMetadataStep1 && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(rootMetadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 2: Copy the new keys to the server</h2>
          <div className="space-y-4">
            <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
              <div className="flex items-start">
                <i className="fas fa-exclamation-triangle text-red-500 mr-3 mt-0.5 text-xl"></i>
                <div className="flex-1">
                  <p className="text-theme-primary text-sm leading-relaxed">
                    Copy <code className="bg-theme-input px-1 rounded">out/online-keys/*</code> into <code className="bg-theme-input px-1 rounded">ONLINE_KEY_DIR</code> on
                    the faynosync API server <strong>before</strong> submitting the metadata below. Once the new root metadata is
                    accepted, the server is expected to sign {selectedRole} with the new key — without the key file it cannot.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 3: Submit metadata</h2>
          <div className="space-y-4">
            <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
              <p className="text-theme-primary text-sm leading-relaxed">
                Paste the contents of <code className="bg-theme-input px-1 rounded">out/root-metadata.json</code> here.
              </p>
            </div>
            <textarea
              value={metadataPayload}
              onChange={(e) => {
                setMetadataPayload(e.target.value);
                setMetadataPayloadError('');
              }}
              placeholder="Paste the contents of out/root-metadata.json here..."
              rows={8}
              className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                metadataPayloadError ? 'border-red-500' : 'border-theme'
              }`}
            />
            {metadataPayloadError && <p className="text-red-500 text-sm">{metadataPayloadError}</p>}
            <button
              onClick={handleSubmitMetadata}
              disabled={!selectedApp || !metadataPayload.trim() || submittingMetadata}
              className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submittingMetadata ? (
                <>
                  <i className="fas fa-spinner fa-spin mr-2"></i>
                  Submitting...
                </>
              ) : (
                <>
                  <i className="fas fa-paper-plane mr-2"></i>
                  Submit Metadata
                </>
              )}
            </button>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 4: Submit signatures</h2>
          <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <p className="text-theme-primary text-sm leading-relaxed mb-2">
              Submit the files from <code className="bg-theme-input px-1 rounded">out/signatures/</code> one at a time. Only the
              current root keys sign here, so there are no <code className="bg-theme-input px-1 rounded">root-new-*</code> files —
              the root keys themselves are not changing.
            </p>
            <p className="text-theme-primary text-sm leading-relaxed">
              Errors about "not enough signatures" or "threshold not reached" are expected until enough signatures are in.
            </p>
          </div>
          <div className="space-y-4">
            <textarea
              value={signaturePayload}
              onChange={(e) => {
                setSignaturePayload(e.target.value);
                setSignaturePayloadError('');
              }}
              placeholder='Paste signature JSON here (e.g., {"keyid": "...", "sig": "..."})'
              rows={6}
              className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                signaturePayloadError ? 'border-red-500' : 'border-theme'
              }`}
            />
            {signaturePayloadError && <p className="text-red-500 text-sm">{signaturePayloadError}</p>}

            {signatureStatus === 'success' && (
              <div className="p-4 bg-green-500 bg-opacity-10 border border-green-500 rounded-lg">
                <p className="text-green-500 font-semibold">Metadata update finished successfully.</p>
              </div>
            )}

            {signatureStatus === 'partial' && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <p className="text-blue-500 font-semibold">Signature added successfully.</p>
              </div>
            )}

            {signatureStatus === 'threshold' && (
              <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <p className="text-yellow-500 font-semibold">Threshold not met.</p>
              </div>
            )}

            {signatureStatus === 'error' && (
              <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
                <p className="text-red-500 font-semibold mb-2">Error submitting signature</p>
                <p className="text-theme-primary text-sm font-mono">{signatureErrorMessage}</p>
              </div>
            )}

            <div className="flex gap-2 items-center flex-wrap">
              <button
                onClick={handleSubmitSignature}
                disabled={!selectedApp || !signaturePayload.trim() || submittingSignature}
                className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submittingSignature ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Submitting...
                  </>
                ) : (
                  <>
                    <i className="fas fa-paper-plane mr-2"></i>
                    Submit Signature
                  </>
                )}
              </button>

              <button
                onClick={handleCheckMetadataStatus}
                disabled={!selectedApp || checkingMetadataStatus}
                className="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {checkingMetadataStatus ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Checking...
                  </>
                ) : (
                  <>
                    <i className="fas fa-check-circle mr-2"></i>
                    Check Status
                  </>
                )}
              </button>

              <button
                onClick={handleGetCurrentRoot}
                disabled={!selectedApp || loadingRootMetadata}
                className="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingRootMetadata ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Loading...
                  </>
                ) : (
                  <>
                    <i className="fas fa-download mr-2"></i>
                    Get current root
                  </>
                )}
              </button>

              <button
                onClick={handleDeleteSigningMetadata}
                disabled={!selectedApp || deletingSigningMetadata}
                className="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {deletingSigningMetadata ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Deleting...
                  </>
                ) : (
                  <>
                    <i className="fas fa-trash mr-2"></i>
                    Delete signing metadata
                  </>
                )}
              </button>
            </div>

            {rootMetadata && (
              <div>
                <button
                  onClick={() => setShowRootMetadataStep4(!showRootMetadataStep4)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showRootMetadataStep4 ? 'up' : 'down'} mr-2`}></i>
                  Current Root Metadata {showRootMetadataStep4 ? '(click to hide)' : '(click to expand)'}
                </button>
                {showRootMetadataStep4 && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(rootMetadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {metadataStatusResult === 'finished' && (
              <div className="p-4 bg-green-500 bg-opacity-10 border border-green-500 rounded-lg">
                <p className="text-green-500 font-semibold">Metadata update finished.</p>
              </div>
            )}
            {metadataStatusResult === 'threshold-not-met' && (
              <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <p className="text-yellow-500 font-semibold">Threshold not reached yet.</p>
              </div>
            )}
            {metadataStatusResult === 'in-progress' && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <p className="text-blue-500 font-semibold">Metadata update in progress.</p>
              </div>
            )}
            {metadataStatusResult === 'error' && (
              <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
                <p className="text-red-500 font-semibold">Error checking status.</p>
              </div>
            )}
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 5: Update metadata files</h2>
          <MetadataUpdatePanel
            onUpdateMetadata={onUpdateMetadata}
            title="Update Metadata Files"
            description="Required, not optional: until the server re-signs with the new key, the repository keeps serving the rotated role signed by the old one, and clients fail verification. Select which roles to update, or leave all unchecked to update all roles (timestamp, targets, snapshot)."
          />

          <h2 className="text-lg font-bold text-theme-primary">Step 6: Promote the new keys</h2>
          <div className="space-y-4">
            <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
              <p className="text-theme-primary text-sm leading-relaxed mb-2">
                Once the dashboard reports the update finished, run this on the machine that holds the keys:
              </p>
              <div className="bg-theme-input rounded-lg p-3 mb-3 font-mono text-xs text-theme-primary overflow-x-auto">
                <div className="whitespace-pre">tuf-kms fetch</div>
              </div>
              <p className="text-theme-primary text-sm leading-relaxed">
                It re-verifies the repository and reconciles the keystore against it: the new {selectedRole} keys go from
                pending to active, the keys they replaced become retired, and thresholds are re-read. Nothing is promoted
                until the repository actually serves them, so a submission that never landed cannot leave the keystore out
                of sync. It also names the replaced keys to delete from <code className="bg-theme-input px-1 rounded">ONLINE_KEY_DIR</code>,
                and clears <code className="bg-theme-input px-1 rounded">out/</code>, which by then holds a spent submission
                and private keys with no reason to stay on disk.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
