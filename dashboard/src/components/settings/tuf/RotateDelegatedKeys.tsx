import React, { useState } from 'react';
import axiosInstance from '@/config/axios';
import { useToast } from '@/hooks/useToast';
import { deleteSigningMetadata } from '@/components/settings/tuf/deleteSigningMetadata';

interface RotateDelegatedKeysProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  onSaveToHistory: (entry: Omit<import('@/components/settings/tuf/types').TufHistoryEntry, 'id'>) => void;
  onCheckTufTasks: (taskId?: string) => void;
}

const isThresholdNotMetError = (message: string): boolean => {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('threshold not reached') ||
    normalized.includes('not enough signatures') ||
    normalized.includes('progress:')
  );
};

const normalizeTrustedTargetsMetadata = (value: unknown): any | null => {
  if (!value) {
    return null;
  }
  if (typeof value === 'string') {
    try {
      return normalizeTrustedTargetsMetadata(JSON.parse(value));
    } catch {
      return null;
    }
  }
  if (typeof value !== 'object') {
    return null;
  }
  const candidate = value as Record<string, any>;
  if (candidate.signed?.version && candidate.signed?.expires) {
    return candidate;
  }
  if (candidate.data?.trusted_targets) {
    return normalizeTrustedTargetsMetadata(candidate.data.trusted_targets);
  }
  if (candidate.trusted_targets) {
    return normalizeTrustedTargetsMetadata(candidate.trusted_targets);
  }
  return null;
};

const normalizeTrustedDelegatedMetadata = (value: unknown): any | null => {
  if (!value) {
    return null;
  }
  if (typeof value === 'string') {
    try {
      return normalizeTrustedDelegatedMetadata(JSON.parse(value));
    } catch {
      return null;
    }
  }
  if (typeof value !== 'object') {
    return null;
  }
  const candidate = value as Record<string, any>;
  if (candidate.signed?.version && candidate.signed?.expires) {
    return candidate;
  }
  if (candidate.data?.trusted_delegated) {
    return normalizeTrustedDelegatedMetadata(candidate.data.trusted_delegated);
  }
  if (candidate.trusted_delegated) {
    return normalizeTrustedDelegatedMetadata(candidate.trusted_delegated);
  }
  return null;
};

export const RotateDelegatedKeys: React.FC<RotateDelegatedKeysProps> = ({
  selectedApp,
  isBootstrapSuccess,
  onSaveToHistory,
  onCheckTufTasks,
}) => {
  const { toastSuccess, toastError } = useToast();

  const [showRotateDelegatedKeys, setShowRotateDelegatedKeys] = useState(false);
  const [roleName, setRoleName] = useState('default');
  const [keyCount, setKeyCount] = useState(1);
  const [threshold, setThreshold] = useState(1);

  const [targetsMetadata, setTargetsMetadata] = useState<any>(null);
  const [delegatedMetadata, setDelegatedMetadata] = useState<any>(null);
  const [loadingTargetsMetadata, setLoadingTargetsMetadata] = useState(false);
  const [loadingDelegatedMetadata, setLoadingDelegatedMetadata] = useState(false);
  const [showTargetsMetadata, setShowTargetsMetadata] = useState(false);
  const [showDelegatedMetadata, setShowDelegatedMetadata] = useState(false);

  const [rotationRequestPayload, setRotationRequestPayload] = useState('');
  const [rotationRequestError, setRotationRequestError] = useState('');
  const [submittingRotationRequest, setSubmittingRotationRequest] = useState(false);

  const [signaturePayload, setSignaturePayload] = useState('');
  const [signaturePayloadError, setSignaturePayloadError] = useState('');
  const [submittingSignature, setSubmittingSignature] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState('');
  const [signatureStatusMessage, setSignatureStatusMessage] = useState('');
  const [signatureErrorMessage, setSignatureErrorMessage] = useState('');

  const [checkingSigningQueue, setCheckingSigningQueue] = useState(false);
  const [signingQueueMessage, setSigningQueueMessage] = useState('');
  const [deletingSigningMetadata, setDeletingSigningMetadata] = useState(false);

  const normalizedRoleName = roleName.trim() || 'default';

  const rotateCommand = `tuf-kms rotate delegated ${normalizedRoleName} \\\n  --keys ${keyCount} \\\n  --threshold ${threshold}`;

  const handleCopyToClipboard = async (value: string, successMessage: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toastSuccess(successMessage);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      toastError('Failed to copy');
    }
  };

  const handleFetchCurrentTargets = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    setLoadingTargetsMetadata(true);
    try {
      const response = await axiosInstance.get(`/tuf/v1/metadata/targets?appName=${encodeURIComponent(selectedApp)}`);
      const normalized = normalizeTrustedTargetsMetadata(response.data);
      if (!normalized) {
        throw new Error('Invalid response: missing trusted_targets');
      }
      setTargetsMetadata(normalized);
      toastSuccess('Targets metadata loaded successfully!');
    } catch (error: any) {
      console.error('Failed to fetch targets metadata:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to fetch targets metadata';
      toastError(errorMessage);
      setTargetsMetadata(null);
    } finally {
      setLoadingTargetsMetadata(false);
    }
  };

  const handleFetchCurrentDelegated = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    if (!normalizedRoleName) {
      toastError('Role name is required');
      return;
    }
    setLoadingDelegatedMetadata(true);
    try {
      const response = await axiosInstance.get(
        `/tuf/v1/metadata/delegated?appName=${encodeURIComponent(selectedApp)}&roleName=${encodeURIComponent(normalizedRoleName)}`
      );
      const normalized = normalizeTrustedDelegatedMetadata(response.data);
      if (!normalized) {
        throw new Error('Invalid response: missing trusted_delegated');
      }
      setDelegatedMetadata(normalized);
      toastSuccess('Delegated metadata loaded successfully!');
    } catch (error: any) {
      console.error('Failed to fetch delegated metadata:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to fetch delegated metadata';
      toastError(errorMessage);
      setDelegatedMetadata(null);
    } finally {
      setLoadingDelegatedMetadata(false);
    }
  };

  const handleSubmitRotationRequest = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    if (!rotationRequestPayload.trim()) {
      setRotationRequestError('Rotation request payload is required');
      return;
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(rotationRequestPayload);
      setRotationRequestError('');
    } catch {
      setRotationRequestError('Invalid JSON format');
      return;
    }

    setSubmittingRotationRequest(true);
    try {
      const response = await axiosInstance.post(
        `/tuf/v1/metadata/delegated/rotate?appName=${encodeURIComponent(selectedApp)}`,
        parsedPayload
      );
      const responseData = response.data?.data;
      if (!responseData?.task_id) {
        throw new Error('Invalid response: missing task_id');
      }

      toastSuccess('Delegated rotation staged successfully!');
      setRotationRequestPayload('');

      onSaveToHistory({
        timestamp: responseData.last_update || new Date().toISOString(),
        appName: selectedApp,
        operation: 'metadata-update',
        status: 'pending',
        taskId: responseData.task_id,
      });
      setTimeout(() => onCheckTufTasks(responseData.task_id), 1000);
    } catch (error: any) {
      console.error('Failed to stage delegated rotation:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to stage delegated rotation';
      toastError(errorMessage);

      onSaveToHistory({
        timestamp: new Date().toISOString(),
        appName: selectedApp,
        operation: 'metadata-update',
        status: 'failed',
      });
    } finally {
      setSubmittingRotationRequest(false);
    }
  };

  const handleCheckSigningQueue = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    setCheckingSigningQueue(true);
    setSigningQueueMessage('');
    try {
      const response = await axiosInstance.get(`/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`);
      const message = response.data?.message || response.data?.data?.message || 'Signing queue checked successfully';
      setSigningQueueMessage(message);
      toastSuccess(message);
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.response?.data?.error || error.message || 'Failed to check signing queue';
      setSigningQueueMessage(errorMessage);
      toastError(errorMessage);
    } finally {
      setCheckingSigningQueue(false);
    }
  };

  const handleSubmitSignaturePayload = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }
    if (!signaturePayload.trim()) {
      setSignaturePayloadError('Signature payload is required');
      return;
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(signaturePayload);
      setSignaturePayloadError('');
    } catch {
      setSignaturePayloadError('Invalid JSON format');
      return;
    }

    setSubmittingSignature(true);
    setSignatureStatus('');
    setSignatureStatusMessage('');
    setSignatureErrorMessage('');

    try {
      const response = await axiosInstance.post(
        `/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`,
        parsedPayload
      );
      const message = response.data?.message || response.data?.data?.message || '';
      const normalizedMessage = message.toLowerCase();

      if (
        normalizedMessage.includes('signing complete') ||
        normalizedMessage.includes('metadata update finished') ||
        normalizedMessage.includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        setSignatureStatusMessage(message || 'Signing complete.');
        toastSuccess(message || 'Signing complete');
      } else {
        setSignatureStatus('partial');
        setSignatureStatusMessage(message || 'Signature payload submitted successfully.');
        toastSuccess(message || 'Signature payload submitted successfully.');
      }

      setSignaturePayload('');
    } catch (error: any) {
      const errorDetail = error.response?.data?.error || '';
      const errorMessage = error.response?.data?.message || '';
      const fullErrorMessage = errorDetail || errorMessage || error.message || 'Failed to submit signature payload';

      if (isThresholdNotMetError(fullErrorMessage)) {
        setSignatureStatus('threshold');
        setSignatureStatusMessage('');
        setSignatureErrorMessage(fullErrorMessage);
        toastError('Threshold not met yet. Continue submitting required signatures.');
        setSignaturePayload('');
      } else {
        setSignatureStatus('error');
        setSignatureStatusMessage('');
        setSignatureErrorMessage(fullErrorMessage);
        toastError(fullErrorMessage);
      }
    } finally {
      setSubmittingSignature(false);
    }
  };

  const handleDeleteSigningMetadata = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }

    setDeletingSigningMetadata(true);
    try {
      const rolesToDelete = ['targets', normalizedRoleName];
      const uniqueRoles = Array.from(new Set(rolesToDelete));
      const results: string[] = [];

      for (const role of uniqueRoles) {
        const result = await deleteSigningMetadata({
          appName: selectedApp,
          role,
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

        results.push(`${role}: ${result.message || 'Signing metadata deleted successfully.'}`);
      }

      toastSuccess(results.join(' | '));
      setSignatureStatus('');
      setSignatureStatusMessage('');
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
        onClick={() => setShowRotateDelegatedKeys(!showRotateDelegatedKeys)}
        className="flex items-center justify-between w-full text-left text-theme-primary hover:text-theme-button-primary transition-colors"
      >
        <h2 className="text-lg font-bold">Rotate Delegated Role Keys</h2>
        <i className={`fas fa-chevron-${showRotateDelegatedKeys ? 'up' : 'down'}`}></i>
      </button>

      {showRotateDelegatedKeys && (
        <div className="mt-6 space-y-6">
          <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
            <p className="text-theme-primary text-sm leading-relaxed mb-2">
              This flow rotates the keys of a delegated role (for example, <code className="bg-theme-input px-1 rounded">default</code>).
              It rewrites targets metadata with the new delegation and bumps the delegated role's own metadata, then signs both
              through the signing API.
            </p>
            <p className="text-theme-primary text-sm leading-relaxed">
              Root is not involved: the change is authorised by the targets keys, which are online keys.
              <code className="bg-theme-input px-1 rounded ml-1">tuf-kms rotate delegated</code> therefore does not ask for the root
              passphrase.
            </p>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 1: Rotate delegated role keys</h2>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-theme-primary mb-2">Delegated role name</label>
                <input
                  type="text"
                  value={roleName}
                  onChange={(e) => setRoleName(e.target.value)}
                  className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                  placeholder="default"
                />
              </div>
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
            </div>

            <div>
              <label className="block text-theme-primary mb-2">Run on the machine that holds the keystore</label>
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
                    The command fetches and verifies the current metadata itself, then writes:
                  </p>
                  <ul className="text-theme-primary text-sm leading-relaxed list-disc list-inside ml-2 space-y-1 mb-3">
                    <li><code className="bg-theme-input px-1 rounded">out/online-keys/</code> — the new {normalizedRoleName} keys, for Step 2</li>
                    <li><code className="bg-theme-input px-1 rounded">out/delegated-rotation-request.json</code> — targets plus the delegated role metadata, for Step 3</li>
                    <li><code className="bg-theme-input px-1 rounded">out/signatures/targets-*.json</code> and <code className="bg-theme-input px-1 rounded">out/signatures/{normalizedRoleName}-*.json</code> — the sign payloads, for Step 4</li>
                  </ul>
                  <p className="text-theme-primary text-sm leading-relaxed mb-2">
                    New keys use the key type stored in <code className="bg-theme-input px-1 rounded">tuf-kms.yaml</code>. Both metadata
                    files keep the lifetime they have now, and there is no flag to change it: the server recomputes both from
                    its own settings the next time it re-signs, so any value chosen here would last only until the next
                    artifact is published.
                  </p>
                  <p className="text-theme-primary text-sm leading-relaxed">
                    <strong>No network on that machine?</strong> Run <code className="bg-theme-input px-1 rounded">tuf-kms fetch</code> where
                    there is, carry <code className="bg-theme-input px-1 rounded">trust/</code> over, and add <code className="bg-theme-input px-1 rounded">--trust-dir /media/usb/trust</code>.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-2 items-center flex-wrap">
              <button
                onClick={handleFetchCurrentTargets}
                disabled={!selectedApp || loadingTargetsMetadata}
                className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingTargetsMetadata ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Loading...
                  </>
                ) : (
                  <>
                    <i className="fas fa-download mr-2"></i>
                    Get current targets
                  </>
                )}
              </button>
              {targetsMetadata && (
                <button
                  onClick={() => handleCopyToClipboard(JSON.stringify(targetsMetadata, null, 2), 'Targets metadata copied successfully!')}
                  className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors"
                >
                  <i className="fas fa-copy mr-2"></i>
                  Copy Targets Metadata
                </button>
              )}
              <button
                onClick={handleFetchCurrentDelegated}
                disabled={!selectedApp || loadingDelegatedMetadata}
                className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingDelegatedMetadata ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Loading...
                  </>
                ) : (
                  <>
                    <i className="fas fa-download mr-2"></i>
                    Get current delegated
                  </>
                )}
              </button>
              {delegatedMetadata && (
                <button
                  onClick={() => handleCopyToClipboard(JSON.stringify(delegatedMetadata, null, 2), 'Delegated metadata copied successfully!')}
                  className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors"
                >
                  <i className="fas fa-copy mr-2"></i>
                  Copy Delegated Metadata
                </button>
              )}
            </div>

            {targetsMetadata && (
              <div>
                <button
                  onClick={() => setShowTargetsMetadata(!showTargetsMetadata)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showTargetsMetadata ? 'up' : 'down'} mr-2`}></i>
                  Current Targets Metadata {showTargetsMetadata ? '(click to hide)' : '(click to expand)'}
                </button>
                {showTargetsMetadata && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(targetsMetadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {delegatedMetadata && (
              <div>
                <button
                  onClick={() => setShowDelegatedMetadata(!showDelegatedMetadata)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showDelegatedMetadata ? 'up' : 'down'} mr-2`}></i>
                  Current Delegated Metadata {showDelegatedMetadata ? '(click to hide)' : '(click to expand)'}
                </button>
                {showDelegatedMetadata && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(delegatedMetadata, null, 2)}
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
                    the faynosync API server <strong>before</strong> staging the rotation below. The server signs {normalizedRoleName} with
                    those keys and cannot do it without the files.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 3: Stage metadata on backend</h2>
          <div className="space-y-4">
            <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
              <p className="text-theme-primary text-sm leading-relaxed">
                Paste the contents of <code className="bg-theme-input px-1 rounded">out/delegated-rotation-request.json</code> here.
              </p>
            </div>
            <textarea
              value={rotationRequestPayload}
              onChange={(e) => {
                setRotationRequestPayload(e.target.value);
                setRotationRequestError('');
              }}
              placeholder="Paste the contents of out/delegated-rotation-request.json here..."
              rows={8}
              className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                rotationRequestError ? 'border-red-500' : 'border-theme'
              }`}
            />
            {rotationRequestError && <p className="text-red-500 text-sm">{rotationRequestError}</p>}
            <button
              onClick={handleSubmitRotationRequest}
              disabled={!selectedApp || !rotationRequestPayload.trim() || submittingRotationRequest}
              className="bg-yellow-500 text-black px-4 py-2 rounded-lg hover:bg-yellow-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submittingRotationRequest ? (
                <>
                  <i className="fas fa-spinner fa-spin mr-2"></i>
                  Submitting...
                </>
              ) : (
                <>
                  <i className="fas fa-paper-plane mr-2"></i>
                  Stage Delegated Rotation
                </>
              )}
            </button>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">Step 4: Submit each sign payload</h2>
          <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <p className="text-theme-primary text-sm leading-relaxed mb-2">
              Submit the files from <code className="bg-theme-input px-1 rounded">out/signatures/</code> one at a time — the
              <code className="bg-theme-input px-1 rounded mx-1">targets-*</code> payloads first, then the
              <code className="bg-theme-input px-1 rounded mx-1">{normalizedRoleName}-*</code> ones. Each file already carries its own
              role, so paste it as it is.
            </p>
            <p className="text-theme-primary text-sm leading-relaxed">
              "Threshold not reached" between payloads is expected. Use "Check Status" to see what the signing queue is still
              waiting for.
            </p>
          </div>
          <div className="space-y-4">
            <textarea
              value={signaturePayload}
              onChange={(e) => {
                setSignaturePayload(e.target.value);
                setSignaturePayloadError('');
              }}
              placeholder='Paste sign payload JSON and send it to /tuf/v1/metadata/sign?appName=...'
              rows={6}
              className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                signaturePayloadError ? 'border-red-500' : 'border-theme'
              }`}
            />
            {signaturePayloadError && <p className="text-red-500 text-sm">{signaturePayloadError}</p>}

            {signatureStatus === 'success' && (
              <div className="p-4 bg-green-500 bg-opacity-10 border border-green-500 rounded-lg">
                <p className="text-green-500 font-semibold">{signatureStatusMessage || 'Signing complete.'}</p>
              </div>
            )}
            {signatureStatus === 'partial' && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <p className="text-blue-500 font-semibold">
                  {signatureStatusMessage || 'Signature accepted. Continue sending remaining payloads.'}
                </p>
              </div>
            )}
            {signatureStatus === 'threshold' && (
              <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <p className="text-yellow-500 font-semibold">Threshold not reached yet.</p>
                {signatureErrorMessage && <p className="text-theme-primary text-sm font-mono mt-2">{signatureErrorMessage}</p>}
              </div>
            )}
            {signatureStatus === 'error' && (
              <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
                <p className="text-red-500 font-semibold">Error submitting signature payload.</p>
                {signatureErrorMessage && <p className="text-theme-primary text-sm font-mono mt-2">{signatureErrorMessage}</p>}
              </div>
            )}

            <div className="flex gap-2 items-center flex-wrap">
              <button
                onClick={handleSubmitSignaturePayload}
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
                    Submit Sign Payload
                  </>
                )}
              </button>

              <button
                onClick={handleCheckSigningQueue}
                disabled={!selectedApp || checkingSigningQueue}
                className="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {checkingSigningQueue ? (
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
          </div>

            {signingQueueMessage && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <p className="text-theme-primary text-sm">{signingQueueMessage}</p>
              </div>
            )}

          <h2 className="text-lg font-bold text-theme-primary">Step 5: Promote the new keys</h2>
          <div className="space-y-4">
            <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
              <p className="text-theme-primary text-sm leading-relaxed mb-2">
                Once the dashboard reports signing complete, run this on the machine that holds the keystore:
              </p>
              <div className="bg-theme-input rounded-lg p-3 mb-3 font-mono text-xs text-theme-primary overflow-x-auto">
                <div className="whitespace-pre">tuf-kms fetch</div>
              </div>
              <p className="text-theme-primary text-sm leading-relaxed">
                It re-verifies the repository and promotes the new {normalizedRoleName} keys from pending to active. Nothing is
                promoted until the repository actually serves them, so a rotation that never landed cannot leave the keystore
                out of sync.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
