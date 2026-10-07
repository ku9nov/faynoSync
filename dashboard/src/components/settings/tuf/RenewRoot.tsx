import React, { useState, useEffect } from 'react';
import { useToast } from '@/hooks/useToast';
import axiosInstance from '@/config/axios';
import { deleteSigningMetadata } from '@/components/settings/tuf/deleteSigningMetadata';
import { TufHistoryEntry } from '@/components/settings/tuf/types';

interface RenewRootProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  onSaveToHistory: (entry: Omit<TufHistoryEntry, 'id'>) => void;
  onCheckTufTasks: (taskId?: string) => void;
}

interface SignatureProgress {
  collected: number;
  total: number;
  remaining: number;
  signedKeys: string[];
  missingKeys: string[];
}

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

const parseKeyList = (message: string, label: string): string[] => {
  const match = message.match(new RegExp(`${label}:\\s*\\[([^\\]]+)\\]`, 'i'));
  return match ? match[1].trim().split(/\s+/).filter((k) => k.length > 0) : [];
};

export const RenewRoot: React.FC<RenewRootProps> = ({
  selectedApp,
  isBootstrapSuccess,
  onSaveToHistory,
  onCheckTufTasks,
}) => {
  const [showRenewRoot, setShowRenewRoot] = useState(false);
  const [expirationDays, setExpirationDays] = useState<number>(364);
  const [rootMetadata, setRootMetadata] = useState<any>(null);
  const [rootMetadataAppName, setRootMetadataAppName] = useState<string | null>(null);
  const [showRootMetadataStep1, setShowRootMetadataStep1] = useState(false);
  const [showRootMetadataStep3, setShowRootMetadataStep3] = useState(false);
  const [loadingRootMetadata, setLoadingRootMetadata] = useState(false);
  const [metadataPayload, setMetadataPayload] = useState<string>('');
  const [metadataPayloadError, setMetadataPayloadError] = useState<string>('');
  const [submittingMetadata, setSubmittingMetadata] = useState(false);
  const [signaturePayload, setSignaturePayload] = useState<string>('');
  const [signaturePayloadError, setSignaturePayloadError] = useState<string>('');
  const [submittingSignature, setSubmittingSignature] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState<string>('');
  const [signatureErrorMessage, setSignatureErrorMessage] = useState<string>('');
  const [signatureProgress, setSignatureProgress] = useState<SignatureProgress | null>(null);
  const [checkingMetadataStatus, setCheckingMetadataStatus] = useState(false);
  const [metadataStatusResult, setMetadataStatusResult] = useState<string | null>(null);
  const [deletingSigningMetadata, setDeletingSigningMetadata] = useState(false);
  const { toastSuccess, toastError } = useToast();

  const renewCommand = `tuf-kms renew root \\\n  --expires ${expirationDays}`;

  const currentVersion = rootMetadata?.signed?.version ?? null;
  const currentExpires = rootMetadata?.signed?.expires ?? null;
  const rootThreshold = rootMetadata?.signed?.roles?.root?.threshold ?? null;

  useEffect(() => {
    setRootMetadata(null);
    setRootMetadataAppName(null);
  }, [selectedApp]);

  const handleCopyRenewCommand = async () => {
    try {
      await navigator.clipboard.writeText(renewCommand);
      toastSuccess('Command copied to clipboard successfully!');
    } catch (err) {
      console.error('Failed to copy command:', err);
      toastError('Failed to copy command');
    }
  };

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

  const handleGetCurrentRoot = async () => {
    if (!selectedApp) {
      toastError('Please select an app');
      return;
    }

    await fetchCurrentRootMetadata(true);
  };

  useEffect(() => {
    if (!showRenewRoot || !selectedApp || !isBootstrapSuccess || loadingRootMetadata) {
      return;
    }

    if (rootMetadata && rootMetadataAppName === selectedApp) {
      return;
    }

    void fetchCurrentRootMetadata(false);
  }, [
    showRenewRoot,
    selectedApp,
    isBootstrapSuccess,
    loadingRootMetadata,
    rootMetadata,
    rootMetadataAppName,
  ]);

  const handleCopyRootMetadata = async () => {
    if (rootMetadata) {
      try {
        const jsonString = JSON.stringify(rootMetadata, null, 2);
        await navigator.clipboard.writeText(jsonString);
        toastSuccess('Root metadata copied to clipboard successfully!');
      } catch (err) {
        console.error('Failed to copy root metadata:', err);
        toastError('Failed to copy root metadata');
      }
    }
  };

  const handleMetadataPayloadChange = (value: string) => {
    setMetadataPayload(value);
    setMetadataPayloadError('');
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
    } catch (e) {
      setMetadataPayloadError('Invalid JSON format');
      return;
    }

    setSubmittingMetadata(true);
    try {
      const payload = {
        metadata: {
          root: parsedMetadata,
        },
      };

      const response = await axiosInstance.post(
        `/tuf/v1/metadata?appName=${encodeURIComponent(selectedApp)}`,
        payload
      );

      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }

      const taskId = responseData.task_id;
      const lastUpdate = responseData.last_update;

      if (!taskId) {
        throw new Error('Invalid response: missing task_id');
      }

      toastSuccess('Metadata submitted successfully!');
      setMetadataPayload('');

      onSaveToHistory({
        timestamp: lastUpdate || new Date().toISOString(),
        appName: selectedApp,
        operation: 'root-meta-update',
        status: 'pending',
        taskId: taskId,
      });

      setTimeout(() => {
        onCheckTufTasks(taskId);
      }, 1000);
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

  const handleSignaturePayloadChange = (value: string) => {
    setSignaturePayload(value);
    setSignaturePayloadError('');
    setSignatureStatus('');
    setSignatureErrorMessage('');
    setSignatureProgress(null);

    if (value.trim()) {
      try {
        const parsed = JSON.parse(value);
        if (!parsed.keyid || !parsed.sig) {
          setSignaturePayloadError('Signature must contain keyid and sig fields');
        }
      } catch (e) {
        // Error will be shown on submit
      }
    }
  };

  // The server counts a renew as a rotation, so its progress line reports
  // threshold * 2 with every signature landing in the "old" bucket. Only the
  // collected count is meaningful here; the real target is the root threshold.
  const parseSignatureProgress = (errorMessage: string): SignatureProgress | null => {
    const progressMatch = errorMessage.match(/Progress:\s*(\d+)\/(\d+)\s+signatures\s+collected/i);
    if (!progressMatch) {
      return null;
    }

    const collected = parseInt(progressMatch[1], 10);
    const reportedTotal = parseInt(progressMatch[2], 10);
    const total = rootThreshold ?? Math.max(Math.round(reportedTotal / 2), 1);

    const signedKeys = Array.from(
      new Set([
        ...parseKeyList(errorMessage, 'Old keys signed'),
        ...parseKeyList(errorMessage, 'New keys signed'),
        ...parseKeyList(errorMessage, 'Signed keys'),
      ])
    );

    const missingKeys = Array.from(
      new Set([
        ...parseKeyList(errorMessage, 'Missing old keys'),
        ...parseKeyList(errorMessage, 'Missing new keys'),
        ...parseKeyList(errorMessage, 'Missing keys'),
      ])
    ).filter((key) => !signedKeys.includes(key));

    return {
      collected,
      total,
      remaining: Math.max(total - collected, 0),
      signedKeys,
      missingKeys,
    };
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
      setSignaturePayloadError('');

      if (!parsedSignature.keyid || !parsedSignature.sig) {
        setSignaturePayloadError('Signature must contain keyid and sig fields');
        return;
      }
    } catch (e) {
      setSignaturePayloadError('Invalid JSON format');
      return;
    }

    setSubmittingSignature(true);
    setSignatureStatus('');
    setSignatureErrorMessage('');
    setSignatureProgress(null);

    try {
      const payload = {
        role: 'root',
        signature: parsedSignature,
      };

      const response = await axiosInstance.post(
        `/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`,
        payload
      );

      const responseData = response.data;
      const message = responseData?.message || responseData?.data?.message || '';

      if (
        message === 'Metadata update finished' ||
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Metadata update finished! The renewed root is live.');
        setSignaturePayload('');
      } else if (message) {
        setSignatureStatus('partial');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess(`Signature submitted: ${message}`);
        setSignaturePayload('');
      } else {
        setSignatureStatus('partial');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Signature submitted successfully! Continue submitting more signatures until threshold is reached.');
        setSignaturePayload('');
      }
    } catch (error: any) {
      console.error('Failed to submit signature:', error);

      const errorDetail = error.response?.data?.error || '';
      const errorMessage = error.response?.data?.message || '';
      const fullErrorMessage = errorDetail || errorMessage || error.message || 'Failed to submit signature';

      if (
        fullErrorMessage === 'No metadata pending signing available' ||
        fullErrorMessage.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Metadata update finished! The renewed root is live.');
        setSignaturePayload('');
      } else if (
        fullErrorMessage.includes('not enough signatures') ||
        fullErrorMessage.includes('threshold not reached') ||
        fullErrorMessage.includes('Progress:')
      ) {
        setSignatureStatus('threshold');
        setSignatureErrorMessage(fullErrorMessage);
        setSignatureProgress(parseSignatureProgress(fullErrorMessage));
        toastError('Threshold not reached yet. Continue submitting more signatures.');
        setSignaturePayload('');
      } else {
        setSignatureStatus('error');
        setSignatureErrorMessage(fullErrorMessage);
        setSignatureProgress(parseSignatureProgress(fullErrorMessage));
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
      const response = await axiosInstance.get(
        `/tuf/v1/metadata/sign?appName=${encodeURIComponent(selectedApp)}`
      );

      const responseData = response.data;
      const message = responseData?.message || responseData?.data?.message || '';

      if (
        message === 'Metadata update finished' ||
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setMetadataStatusResult('finished');
        toastSuccess('Metadata update finished! The renewed root is live.');
      } else if (message) {
        setMetadataStatusResult('in-progress');
        toastSuccess(`Status: ${message}`);
      } else {
        setMetadataStatusResult('unknown');
        toastSuccess('Status checked successfully');
      }
    } catch (error: any) {
      console.error('Failed to check metadata status:', error);
      const errorMessage = error.response?.data?.message || error.response?.data?.error || error.message || 'Failed to check metadata status';

      if (errorMessage.includes('not enough signatures') || errorMessage.includes('threshold not reached')) {
        setMetadataStatusResult('threshold-not-met');
        toastError(`Threshold not reached: ${errorMessage}`);
      } else {
        setMetadataStatusResult('error');
        toastError(errorMessage);
      }
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

        setTimeout(() => {
          onCheckTufTasks(result.taskId);
        }, 1000);

        toastSuccess(result.message || 'Metadata sign delete accepted.');
      } else {
        toastSuccess(result.message || 'No signing process for root.');
      }

      setSignatureStatus('');
      setSignatureErrorMessage('');
      setSignatureProgress(null);
      setSignaturePayload('');
    } catch (error: any) {
      console.error('Failed to delete signing metadata:', error);
      const errorMessage = error.message || 'Failed to delete signing metadata';
      toastError(errorMessage);
    } finally {
      setDeletingSigningMetadata(false);
    }
  };

  const renderProgress = (progress: SignatureProgress) => (
    <div className="space-y-3">
      <div className="bg-theme-input rounded-lg p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-theme-primary font-semibold">Signatures collected</span>
          <span className="text-yellow-500 font-bold">
            {progress.collected} / {progress.total}
          </span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2.5 mb-2">
          <div
            className="bg-yellow-500 h-2.5 rounded-full transition-all duration-300"
            style={{ width: `${Math.min((progress.collected / progress.total) * 100, 100)}%` }}
          ></div>
        </div>
        <p className="text-theme-primary text-xs">
          {progress.remaining} more {progress.remaining === 1 ? 'signature' : 'signatures'} required to reach the root threshold
        </p>
      </div>

      {progress.signedKeys.length > 0 && (
        <div className="bg-theme-input rounded-lg p-3">
          <p className="text-theme-primary text-xs font-semibold mb-2">Keys signed</p>
          <div className="flex flex-wrap gap-1">
            {progress.signedKeys.map((key, idx) => (
              <span
                key={idx}
                className="text-xs bg-green-500 bg-opacity-20 text-green-400 px-2 py-1 rounded font-mono"
              >
                {key.substring(0, 8)}...
              </span>
            ))}
          </div>
        </div>
      )}

      {progress.missingKeys.length > 0 && (
        <div className="bg-theme-input rounded-lg p-3">
          <p className="text-theme-primary text-xs font-semibold mb-2">Keys not signed yet</p>
          <div className="flex flex-wrap gap-1">
            {progress.missingKeys.map((key, idx) => (
              <span
                key={idx}
                className="text-xs bg-yellow-500 bg-opacity-20 text-yellow-400 px-2 py-1 rounded font-mono"
              >
                {key.substring(0, 8)}...
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  if (!selectedApp || !isBootstrapSuccess) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
      <div className="flex items-center justify-between mb-4">
        <button
          onClick={() => setShowRenewRoot(!showRenewRoot)}
          className="flex items-center justify-between flex-1 text-theme-primary hover:text-theme-button-primary transition-colors"
        >
          <h2 className="text-lg font-bold">
            Renew Root
          </h2>
          <i className={`fas fa-chevron-${showRenewRoot ? 'up' : 'down'}`}></i>
        </button>
      </div>

      {showRenewRoot && (
        <>
          <div className="mb-6 p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <div className="flex items-start">
              <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
              <div className="flex-1">
                <h3 className="text-yellow-500 font-semibold mb-2">Root Renewal</h3>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  Renewing publishes a new root version with a later expiry and <strong>the same keys</strong>. Nothing is
                  replaced: <code className="bg-theme-input px-1 rounded">keys</code>, <code className="bg-theme-input px-1 rounded">roles</code> and
                  the threshold stay byte-for-byte identical, and no online key moves. Because the key set does not change, the
                  signatures of the current root keys satisfy both the outgoing and the incoming document — there is a single set
                  of signatures, not an old and a new one.
                </p>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  <strong>Renew or rotate?</strong> Renew when the only thing you need is to push the expiry date out. Rotate when
                  you actually need different root keys — a compromised key, or a change in who holds them. Rotating just to move
                  a date burns every root key for nothing.
                </p>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  Renewal happens offline, like rotation. <code className="bg-theme-input px-1 rounded">tuf-kms renew root</code> builds
                  the new root metadata and signs it with the keys in <code className="bg-theme-input px-1 rounded">keys/root/</code> on
                  your secure machine. The root private keys never leave it — the server only receives the metadata and the
                  signatures you paste below.
                </p>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  <strong>Prerequisites:</strong>
                </p>
                <ul className="text-theme-primary text-sm leading-relaxed list-disc list-inside ml-2 space-y-1 mb-3">
                  <li>The tuf-kms working directory from the initial setup: <code className="bg-theme-input px-1 rounded">tuf-kms.yaml</code>, <code className="bg-theme-input px-1 rounded">keystore.json</code>, <code className="bg-theme-input px-1 rounded">keys/root/</code></li>
                  <li>The passphrase that encrypts <code className="bg-theme-input px-1 rounded">keys/root/</code></li>
                  <li><code className="bg-theme-input px-1 rounded">metadata_url</code> in <code className="bg-theme-input px-1 rounded">tuf-kms.yaml</code> — the command fetches and verifies the current root itself, so there is no file to download by hand</li>
                </ul>
              </div>
            </div>
          </div>

          <h2 className="text-lg font-bold text-theme-primary">
            Step 1: Run on the offline machine
          </h2>
          <div className="mt-4 space-y-4">
            <div>
              <label className="block text-theme-primary mb-2">App Name</label>
              <input
                type="text"
                value={selectedApp}
                disabled
                className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2 disabled:opacity-50"
              />
            </div>

            {rootMetadata && (
              <div className="bg-theme-input rounded-lg p-4 border border-theme">
                <p className="text-theme-primary text-sm">
                  Current root: <strong>version {currentVersion ?? 'unknown'}</strong>
                  {currentExpires && (
                    <> — expires <strong>{currentExpires}</strong></>
                  )}
                  {rootThreshold !== null && (
                    <> — threshold <strong>{rootThreshold}</strong></>
                  )}
                </p>
                <p className="text-xs text-theme-primary opacity-70 mt-1">
                  The renewal publishes version {currentVersion !== null ? currentVersion + 1 : 'N+1'} with the same keys.
                </p>
              </div>
            )}

            <div>
              <label className="block text-theme-primary mb-2">Root expiration (days)</label>
              <input
                type="number"
                value={expirationDays}
                onChange={(e) => {
                  const parsed = parseInt(e.target.value);
                  if (Number.isNaN(parsed)) {
                    setExpirationDays(1);
                    return;
                  }
                  setExpirationDays(Math.min(Math.max(parsed, 1), 365));
                }}
                min="1"
                max="365"
                className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
              />
              <p className="text-xs text-theme-primary opacity-70 mt-1">
                Between 1 and 365, counted from the moment the command runs, not from the current expiry date. The command asks
                for confirmation if the new date is earlier than the one root has now.
              </p>
            </div>

            <div>
              <label className="block text-theme-primary mb-2">Run on the offline machine</label>
              <div className="bg-theme-input rounded-lg p-4 border border-theme">
                <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">{renewCommand}</pre>
                <div className="mt-2 flex gap-2">
                  <button
                    onClick={handleCopyRenewCommand}
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
                    The command asks for the root passphrase, then writes:
                  </p>
                  <ul className="text-theme-primary text-sm leading-relaxed list-disc list-inside ml-2 space-y-1 mb-3">
                    <li><code className="bg-theme-input px-1 rounded">out/root-metadata.json</code> — the new root metadata, for Step 2</li>
                    <li><code className="bg-theme-input px-1 rounded">out/signatures/root-*.json</code> — one signature per active root key, for Step 3</li>
                  </ul>
                  <p className="text-theme-primary text-sm leading-relaxed">
                    Nothing in <code className="bg-theme-input px-1 rounded">keys/root/</code> changes: no key is generated, and none
                    becomes pending or retired.
                  </p>
                  <p className="text-theme-primary text-sm leading-relaxed mt-2">
                    <strong>Air-gapped machine:</strong> run <code className="bg-theme-input px-1 rounded">tuf-kms fetch</code> where there
                    is network, carry <code className="bg-theme-input px-1 rounded">trust/</code> over, and add <code className="bg-theme-input px-1 rounded">--trust-dir /media/usb/trust</code> to
                    the command above.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-2 items-center">
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
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={handleCopyRootMetadata}
                        className="bg-theme-button-primary text-theme-primary px-3 py-1 rounded text-sm hover:bg-theme-button-primary-hover"
                      >
                        <i className="fas fa-copy mr-1"></i>
                        Copy Root Metadata
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="h-px w-full bg-theme-card-hover mt-6"></div>
          <h2 className="text-lg font-bold text-theme-primary mt-6">
            Step 2: Submit metadata
          </h2>
          <div className="mt-6 p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <div className="flex items-start">
              <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
              <div className="flex-1">
                <p className="text-theme-primary text-sm leading-relaxed">
                  Paste the contents of <code className="bg-theme-input px-1 rounded">out/root-metadata.json</code> here. It is the
                  complete document, with both <code className="bg-theme-input px-1 rounded">signed</code> and <code className="bg-theme-input px-1 rounded">signatures</code>.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 space-y-4">
            <div>
              <label className="block text-theme-primary mb-2">Metadata Payload</label>
              <textarea
                value={metadataPayload}
                onChange={(e) => handleMetadataPayloadChange(e.target.value)}
                placeholder="Paste the contents of out/root-metadata.json here..."
                rows={8}
                className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                  metadataPayloadError ? 'border-red-500' : 'border-theme'
                }`}
              />
              {metadataPayloadError && (
                <p className="text-red-500 text-sm mt-1">{metadataPayloadError}</p>
              )}
            </div>

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

          <div className="h-px w-full bg-theme-card-hover mt-6"></div>
          <h2 className="text-lg font-bold text-theme-primary mt-6">
            Step 3: Submit signatures
          </h2>
          <div className="mt-6 p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <div className="flex items-start">
              <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
              <div className="flex-1">
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  Submit the <code className="bg-theme-input px-1 rounded">out/signatures/root-*.json</code> files one at a time.
                  There is one set only — the same keys sign the outgoing and the incoming root.
                </p>
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  <strong>Instructions:</strong>
                </p>
                <ol className="text-theme-primary text-sm leading-relaxed list-decimal list-inside ml-2 space-y-1 mb-3">
                  <li>Open one signature file — it contains a single <code className="bg-theme-input px-1 rounded">{'{"keyid": "...", "sig": "..."}'}</code> object</li>
                  <li>Paste the whole file into the field below</li>
                  <li>Click "Submit Signature"</li>
                  <li>Repeat for every file until you get "Metadata update finished"</li>
                </ol>
                <div className="bg-yellow-500 bg-opacity-20 rounded-lg p-3 mt-3">
                  <p className="text-theme-primary text-sm leading-relaxed">
                    <strong>Note:</strong> errors about "not enough signatures" or "threshold not reached" are expected until
                    enough signatures are in. Keep submitting. The server counts a renewal as a rotation, so its raw message may
                    ask for twice the threshold and for "new" keys that do not exist — the update finishes as soon as the root
                    threshold{rootThreshold !== null ? ` (${rootThreshold})` : ''} is met.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 space-y-4">
            <div>
              <label className="block text-theme-primary mb-2">Signature Payload</label>
              <textarea
                value={signaturePayload}
                onChange={(e) => handleSignaturePayloadChange(e.target.value)}
                placeholder='Paste signature JSON here (e.g., {"keyid": "...", "sig": "..."})'
                rows={6}
                className={`w-full bg-theme-input text-theme-primary border rounded-lg px-4 py-2 font-mono text-sm ${
                  signaturePayloadError ? 'border-red-500' : 'border-theme'
                }`}
              />
              {signaturePayloadError && (
                <p className="text-red-500 text-sm mt-1">{signaturePayloadError}</p>
              )}
            </div>

            {signatureStatus === 'success' && (
              <div className="p-4 bg-green-500 bg-opacity-10 border border-green-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-check-circle text-green-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-green-500 font-semibold mb-1">Metadata update finished!</p>
                    <p className="text-theme-primary text-sm">
                      The renewed root is published with the same keys and the new expiry. Check the "Root-Meta-Update" task in
                      the history to see the result.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {signatureStatus === 'threshold' && (
              <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-yellow-500 font-semibold mb-2">Threshold not reached yet</p>

                    {signatureProgress ? (
                      renderProgress(signatureProgress)
                    ) : signatureErrorMessage && (
                      <p className="text-theme-primary mb-2 font-mono text-xs bg-theme-input p-2 rounded">
                        {signatureErrorMessage}
                      </p>
                    )}

                    <p className="text-theme-primary text-sm mt-3">
                      Continue submitting more signatures. The input field has been cleared for the next signature.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {signatureStatus === 'partial' && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-info-circle text-blue-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-blue-500 font-semibold mb-1">Signature submitted</p>
                    <p className="text-theme-primary text-sm">
                      Continue submitting more signatures until the threshold is met. The input field has been cleared for the next signature.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {signatureStatus === 'error' && (
              <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-exclamation-circle text-red-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-red-500 font-semibold mb-1">Error submitting signature</p>
                    {signatureErrorMessage && (
                      <>
                        <p className="text-theme-primary mb-2 font-mono text-xs bg-theme-input p-2 rounded">
                          {signatureErrorMessage}
                        </p>
                        {signatureProgress && (
                          <div className="mt-3">{renderProgress(signatureProgress)}</div>
                        )}
                      </>
                    )}
                    <p className="text-theme-primary text-sm mt-3">
                      {signatureProgress
                        ? 'Continue submitting more signatures. The input field has been cleared for the next signature.'
                        : 'Please check the error message above and try again.'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            <div className="flex gap-2 items-center">
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
              <div className="mt-4">
                <button
                  onClick={() => setShowRootMetadataStep3(!showRootMetadataStep3)}
                  className="text-theme-primary hover:text-theme-button-primary mb-2 flex items-center"
                >
                  <i className={`fas fa-chevron-${showRootMetadataStep3 ? 'up' : 'down'} mr-2`}></i>
                  Current Root Metadata {showRootMetadataStep3 ? '(click to hide)' : '(click to expand)'}
                </button>
                {showRootMetadataStep3 && (
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(rootMetadata, null, 2)}
                    </pre>
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={handleCopyRootMetadata}
                        className="bg-theme-button-primary text-theme-primary px-3 py-1 rounded text-sm hover:bg-theme-button-primary-hover"
                      >
                        <i className="fas fa-copy mr-1"></i>
                        Copy Root Metadata
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {metadataStatusResult === 'finished' && (
              <div className="p-4 bg-green-500 bg-opacity-10 border border-green-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-check-circle text-green-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-green-500 font-semibold mb-1">Metadata update finished!</p>
                    <p className="text-theme-primary text-sm">
                      The renewed root is published. Check the "Root-Meta-Update" task in the history to see the result.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {metadataStatusResult === 'threshold-not-met' && (
              <div className="p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-yellow-500 font-semibold mb-1">Threshold not reached</p>
                    <p className="text-theme-primary text-sm">
                      Continue submitting more signatures until the threshold is met.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {metadataStatusResult === 'in-progress' && (
              <div className="p-4 bg-blue-500 bg-opacity-10 border border-blue-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-info-circle text-blue-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-blue-500 font-semibold mb-1">Metadata update in progress</p>
                    <p className="text-theme-primary text-sm">
                      The metadata update is still in progress. Continue submitting signatures if needed.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {metadataStatusResult === 'error' && (
              <div className="p-4 bg-red-500 bg-opacity-10 border border-red-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-exclamation-circle text-red-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-red-500 font-semibold mb-1">Error checking status</p>
                    <p className="text-theme-primary text-sm">
                      An error occurred while checking the metadata status. Please try again.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {metadataStatusResult === 'unknown' && (
              <div className="p-4 bg-gray-500 bg-opacity-10 border border-gray-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-question-circle text-gray-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <p className="text-gray-500 font-semibold mb-1">Status unknown</p>
                    <p className="text-theme-primary text-sm">
                      Could not determine the exact status. Please check the response or try submitting more signatures.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="h-px w-full bg-theme-card-hover mt-6"></div>
          <h2 className="text-lg font-bold text-theme-primary mt-6">
            Step 4: Confirm on the offline machine
          </h2>
          <div className="mt-6 p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
            <div className="flex items-start">
              <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
              <div className="flex-1">
                <p className="text-theme-primary text-sm leading-relaxed mb-2">
                  Once you see "Metadata update finished", run this on the machine that holds the keys:
                </p>
                <div className="bg-theme-input rounded-lg p-3 mb-3 font-mono text-xs text-theme-primary overflow-x-auto">
                  <div className="whitespace-pre">tuf-kms fetch</div>
                </div>
                <p className="text-theme-primary text-sm leading-relaxed">
                  No key changed, so there is nothing pending and nothing to promote: the fetch re-verifies the repository and
                  confirms the new root version is live. The keystore is left exactly as it was.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
