import React, { useState, useEffect } from 'react';
import { useToast } from '@/hooks/useToast';
import axiosInstance from '@/config/axios';
import { deleteSigningMetadata } from '@/components/settings/tuf/deleteSigningMetadata';

interface RotateRootKeysProps {
  selectedApp: string;
  isBootstrapSuccess: boolean;
  onSaveToHistory: (entry: Omit<import('@/components/settings/tuf/types').TufHistoryEntry, 'id'>) => void;
  onCheckTufTasks: (taskId?: string) => void;
}

interface SignatureProgress {
  collected: number;
  total: number;
  oldCollected: number;
  newCollected: number;
  remaining: number;
  oldRemaining: number;
  newRemaining: number;
  oldKeysSigned: string[];
  missingOldKeys: string[];
  missingNewKeys: string[];
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

export const RotateRootKeys: React.FC<RotateRootKeysProps> = ({
  selectedApp,
  isBootstrapSuccess,
  onSaveToHistory,
  onCheckTufTasks,
}) => {
  const [showRotateKeys, setShowRotateKeys] = useState(false);
  const [keyCount, setKeyCount] = useState<number>(2);
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

  const rotateCommand = `tuf-kms rotate root \\\n  --keys ${keyCount} \\\n  --root-expires ${expirationDays}`;

  useEffect(() => {
    setRootMetadata(null);
    setRootMetadataAppName(null);
  }, [selectedApp]);

  const handleCopyRotateCommand = async () => {
    try {
      await navigator.clipboard.writeText(rotateCommand);
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
    if (!showRotateKeys || !selectedApp || !isBootstrapSuccess || loadingRootMetadata) {
      return;
    }

    if (rootMetadata && rootMetadataAppName === selectedApp) {
      return;
    }

    void fetchCurrentRootMetadata(false);
  }, [
    showRotateKeys,
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
    
    // Validate JSON on change
    if (value.trim()) {
      try {
        JSON.parse(value);
      } catch (e) {
        // Error will be shown on submit
      }
    }
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

    // Validate JSON
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

      // Save to history with initial status, will be updated when we check the actual status
      onSaveToHistory({
        timestamp: lastUpdate || new Date().toISOString(),
        appName: selectedApp,
        operation: 'root-meta-update',
        status: 'pending', // Will be updated when we check actual status via API
        taskId: taskId,
      });

      // Immediately check the task status to update history with real status
      setTimeout(() => {
        onCheckTufTasks(taskId);
      }, 1000);
    } catch (error: any) {
      console.error('Failed to submit metadata:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to submit metadata';
      toastError(errorMessage);

      // Save failed operation to history
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
    
    // Validate JSON on change
    if (value.trim()) {
      try {
        const parsed = JSON.parse(value);
        // Validate structure
        if (!parsed.keyid || !parsed.sig) {
          setSignaturePayloadError('Signature must contain keyid and sig fields');
        }
      } catch (e) {
        // Error will be shown on submit
      }
    }
  };

  const parseSignatureProgress = (errorMessage: string): SignatureProgress | null => {
    try {
      // Parse progress: "Progress: 1/4 signatures collected (1 old + 0 new). 3 more required (1 old + 2 new)."
      // Make regex more flexible to handle variations in spacing and punctuation
      const progressMatch = errorMessage.match(/Progress:\s*(\d+)\/(\d+)\s+signatures\s+collected\s+\((\d+)\s+old\s+\+\s+(\d+)\s+new\)[.\s]*(\d+)\s+more\s+required\s+\((\d+)\s+old\s+\+\s+(\d+)\s+new\)/i);
      
      if (!progressMatch) {
        console.log('Progress regex did not match. Error message:', errorMessage);
        return null;
      }

      const collected = parseInt(progressMatch[1], 10);
      const total = parseInt(progressMatch[2], 10);
      const oldCollected = parseInt(progressMatch[3], 10);
      const newCollected = parseInt(progressMatch[4], 10);
      const remaining = parseInt(progressMatch[5], 10);
      const oldRemaining = parseInt(progressMatch[6], 10);
      const newRemaining = parseInt(progressMatch[7], 10);

      // Parse old keys signed: "Old keys signed: [key1 key2]."
      const oldKeysSignedMatch = errorMessage.match(/Old keys signed:\s*\[([^\]]+)\]/i);
      const oldKeysSigned = oldKeysSignedMatch 
        ? oldKeysSignedMatch[1].trim().split(/\s+/).filter(k => k.length > 0)
        : [];

      // Parse missing old keys: "Missing old keys: [key1 key2]."
      const missingOldKeysMatch = errorMessage.match(/Missing old keys:\s*\[([^\]]+)\]/i);
      const missingOldKeys = missingOldKeysMatch
        ? missingOldKeysMatch[1].trim().split(/\s+/).filter(k => k.length > 0)
        : [];

      // Parse missing new keys: "Missing new keys: [key1 key2]."
      const missingNewKeysMatch = errorMessage.match(/Missing new keys:\s*\[([^\]]+)\]/i);
      const missingNewKeys = missingNewKeysMatch
        ? missingNewKeysMatch[1].trim().split(/\s+/).filter(k => k.length > 0)
        : [];

      return {
        collected,
        total,
        oldCollected,
        newCollected,
        remaining,
        oldRemaining,
        newRemaining,
        oldKeysSigned,
        missingOldKeys,
        missingNewKeys,
      };
    } catch (e) {
      console.error('Failed to parse signature progress:', e);
      return null;
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

    // Validate JSON
    let parsedSignature;
    try {
      parsedSignature = JSON.parse(signaturePayload);
      setSignaturePayloadError('');
      
      // Validate structure
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
      
      // Check if we got success message
      if (
        message === 'Metadata update finished' || 
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Metadata update finished! Root keys rotation completed successfully.');
        setSignaturePayload(''); // Clear input for next signature if needed
      } else if (message) {
        setSignatureStatus('partial');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess(`Signature submitted: ${message}`);
        setSignaturePayload(''); // Clear input for next signature
      } else {
        setSignatureStatus('partial');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Signature submitted successfully! Continue submitting more signatures until threshold is reached.');
        setSignaturePayload(''); // Clear input for next signature
      }
    } catch (error: any) {
      console.error('Failed to submit signature:', error);
      console.log('Error response data:', error.response?.data);
      
      // Prioritize error field over message field, as it contains detailed progress info
      const errorDetail = error.response?.data?.error || '';
      const errorMessage = error.response?.data?.message || '';
      // Combine both fields, prioritizing error detail which contains progress info
      const fullErrorMessage = errorDetail || errorMessage || error.message || 'Failed to submit signature';
      
      console.log('Full error message:', fullErrorMessage);
      console.log('Contains "not enough signatures":', fullErrorMessage.includes('not enough signatures'));
      console.log('Contains "threshold not reached":', fullErrorMessage.includes('threshold not reached'));
      
      // Check if it's a success message (no metadata pending = all signed)
      if (
        fullErrorMessage === 'No metadata pending signing available' ||
        fullErrorMessage.toLowerCase().includes('no metadata pending')
      ) {
        setSignatureStatus('success');
        setSignatureErrorMessage('');
        setSignatureProgress(null);
        toastSuccess('Metadata update finished! Root keys rotation completed successfully.');
        setSignaturePayload(''); // Clear input
      } else if (
        fullErrorMessage.includes('not enough signatures') || 
        fullErrorMessage.includes('threshold not reached') ||
        fullErrorMessage.includes('Progress:')
      ) {
        // Check if it's a threshold error (expected, continue submitting)
        // Also check for "Progress:" as it indicates threshold progress info
        console.log('Setting status to threshold');
        setSignatureStatus('threshold');
        setSignatureErrorMessage(fullErrorMessage);
        
        // Parse progress information from error message
        const progress = parseSignatureProgress(fullErrorMessage);
        console.log('Parsed progress:', progress);
        setSignatureProgress(progress);
        
        toastError(`Threshold not reached yet. Continue submitting more signatures.`);
        setSignaturePayload(''); // Clear input for next signature
      } else {
        console.log('Setting status to error');
        setSignatureStatus('error');
        setSignatureErrorMessage(fullErrorMessage);
        
        // Try to parse progress even for error status, in case it contains threshold info
        const progress = parseSignatureProgress(fullErrorMessage);
        setSignatureProgress(progress);
        
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
      
      // Check for success conditions
      if (
        message === 'Metadata update finished' || 
        message === 'No metadata pending signing available' ||
        message.toLowerCase().includes('no metadata pending')
      ) {
        setMetadataStatusResult('finished');
        toastSuccess('Metadata update finished! Root keys rotation completed successfully.');
      } else if (message) {
        // If there's a message but it's not a success message, it might be in progress
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
      
      // If we have a task_id, save to history
      if (result.hasTask && result.taskId) {
        onSaveToHistory({
          timestamp: result.lastUpdate || new Date().toISOString(),
          appName: selectedApp,
          operation: 'metadata-update',
          status: 'pending', // Will be updated when we check actual status via API
          taskId: result.taskId,
        });
        
        // Optionally check the task status
        if (result.taskId) {
          setTimeout(() => {
            onCheckTufTasks(result.taskId);
          }, 1000);
        }
        
        toastSuccess(result.message || 'Metadata sign delete accepted.');
      } else {
        // No task means nothing was being signed (success case)
        toastSuccess(result.message || 'No signing process for root.');
      }
      
      // Clear signature status and progress after deletion
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


  if (!selectedApp || !isBootstrapSuccess) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
      <div className="flex items-center justify-between mb-4">
        <button
          onClick={() => setShowRotateKeys(!showRotateKeys)}
          className="flex items-center justify-between flex-1 text-theme-primary hover:text-theme-button-primary transition-colors"
        >
          <h2 className="text-lg font-bold">
            Rotate Root Keys
          </h2>
          <i className={`fas fa-chevron-${showRotateKeys ? 'up' : 'down'}`}></i>
        </button>
      </div>

      {showRotateKeys && (
        <>
              {/* Rotation instructions */}
              <div className="mb-6 p-4 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                <div className="flex items-start">
                  <i className="fas fa-info-circle text-yellow-500 mr-3 mt-0.5 text-xl"></i>
                  <div className="flex-1">
                    <h3 className="text-yellow-500 font-semibold mb-2">Root Keys Rotation</h3>
                    <p className="text-theme-primary text-sm leading-relaxed mb-2">
                      Only need to push root's expiry out? Use the <strong>Renew Root</strong> panel above instead: <code className="bg-theme-input px-1 rounded">tuf-kms renew root --expires N</code> publishes
                      a new root version signed by the keys root already has, so no key is replaced and no online key moves.
                      Rotate only when you actually want new root keys.
                    </p>
                    <p className="text-theme-primary text-sm leading-relaxed mb-2">
                      Root rotation happens offline. <code className="bg-theme-input px-1 rounded">tuf-kms rotate root</code> builds
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
                Step 1: Rotate root keys
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

                <div>
                  <label className="block text-theme-primary mb-2">Count of Keys</label>
                  <input
                    type="number"
                    value={keyCount}
                    onChange={(e) => setKeyCount(parseInt(e.target.value) || 1)}
                    min="1"
                    className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                  />
                  <p className="text-xs text-theme-primary opacity-70 mt-1">
                    How many root keys the role has after the rotation. New keys are generated with the key type stored in tuf-kms.yaml.
                  </p>
                </div>

                <div>
                  <label className="block text-theme-primary mb-2">Root Expiration (days)</label>
                  <input
                    type="number"
                    value={expirationDays}
                    onChange={(e) => setExpirationDays(parseInt(e.target.value) || 1)}
                    min="1"
                    className="w-full bg-theme-input text-theme-primary border border-theme rounded-lg px-4 py-2"
                  />
                  <p className="text-xs text-theme-primary opacity-70 mt-1">
                    Counted from the moment the command runs, not from the current expiry date. Leave the flag out entirely
                    and root keeps the expiry it has now.
                  </p>
                </div>

                <div>
                  <label className="block text-theme-primary mb-2">Run on the offline machine</label>
                  <div className="bg-theme-input rounded-lg p-4 border border-theme">
                    <pre className="text-sm text-theme-primary overflow-x-auto whitespace-pre-wrap">{rotateCommand}</pre>
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={handleCopyRotateCommand}
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
                        <li><code className="bg-theme-input px-1 rounded">out/signatures/root-old-*.json</code> and <code className="bg-theme-input px-1 rounded">out/signatures/root-new-*.json</code> — the signatures, for Step 3</li>
                      </ul>
                      <p className="text-theme-primary text-sm leading-relaxed">
                        The new keys are written to <code className="bg-theme-input px-1 rounded">keys/root/</code> as <strong>pending</strong>. They
                        become the active ones only after Step 4, so a rotation that fails halfway leaves the keystore usable.
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
                      Submit the files from <code className="bg-theme-input px-1 rounded">out/signatures/</code> one at a time. The
                      <code className="bg-theme-input px-1 rounded">root-old-*</code> files prove the current root keys approve the change; the
                      <code className="bg-theme-input px-1 rounded">root-new-*</code> files prove you hold the new ones.
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
                        enough signatures are in. Keep submitting.
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
                          Root keys rotation has been completed successfully. All required signatures have been submitted and the threshold has been met. Now you can check "Root-Meta-Update" task in the history to see the result.
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
                          <div className="space-y-3">
                            {/* Overall Progress */}
                            <div className="bg-theme-input rounded-lg p-3">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-theme-primary font-semibold">Overall Progress</span>
                                <span className="text-yellow-500 font-bold">
                                  {signatureProgress.collected} / {signatureProgress.total}
                                </span>
                              </div>
                              <div className="w-full bg-gray-700 rounded-full h-2.5 mb-2">
                                <div 
                                  className="bg-yellow-500 h-2.5 rounded-full transition-all duration-300"
                                  style={{ width: `${(signatureProgress.collected / signatureProgress.total) * 100}%` }}
                                ></div>
                              </div>
                              <p className="text-theme-primary text-xs">
                                {signatureProgress.remaining} more {signatureProgress.remaining === 1 ? 'signature' : 'signatures'} required
                              </p>
                            </div>

                            {/* Breakdown by Old/New Keys */}
                            <div className="grid grid-cols-2 gap-3">
                              <div className="bg-theme-input rounded-lg p-3">
                                <p className="text-theme-primary text-xs font-semibold mb-1">Old Keys</p>
                                <p className="text-green-400 text-sm font-bold">
                                  {signatureProgress.oldCollected} collected
                                </p>
                                {signatureProgress.oldRemaining > 0 && (
                                  <p className="text-yellow-400 text-xs mt-1">
                                    {signatureProgress.oldRemaining} more needed
                                  </p>
                                )}
                              </div>
                              <div className="bg-theme-input rounded-lg p-3">
                                <p className="text-theme-primary text-xs font-semibold mb-1">New Keys</p>
                                <p className="text-green-400 text-sm font-bold">
                                  {signatureProgress.newCollected} collected
                                </p>
                                {signatureProgress.newRemaining > 0 && (
                                  <p className="text-yellow-400 text-xs mt-1">
                                    {signatureProgress.newRemaining} more needed
                                  </p>
                                )}
                              </div>
                            </div>

                            {/* Signed Keys */}
                            {signatureProgress.oldKeysSigned.length > 0 && (
                              <div className="bg-theme-input rounded-lg p-3">
                                <p className="text-theme-primary text-xs font-semibold mb-2">✓ Old Keys Signed</p>
                                <div className="flex flex-wrap gap-1">
                                  {signatureProgress.oldKeysSigned.map((key, idx) => (
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

                            {/* Missing Keys */}
                            {(signatureProgress.missingOldKeys.length > 0 || signatureProgress.missingNewKeys.length > 0) && (
                              <div className="bg-theme-input rounded-lg p-3">
                                <p className="text-theme-primary text-xs font-semibold mb-2">⚠ Missing Keys</p>
                                {signatureProgress.missingOldKeys.length > 0 && (
                                  <div className="mb-2">
                                    <p className="text-yellow-400 text-xs mb-1">Old Keys:</p>
                                    <div className="flex flex-wrap gap-1">
                                      {signatureProgress.missingOldKeys.map((key, idx) => (
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
                                {signatureProgress.missingNewKeys.length > 0 && (
                                  <div>
                                    <p className="text-yellow-400 text-xs mb-1">New Keys:</p>
                                    <div className="flex flex-wrap gap-1">
                                      {signatureProgress.missingNewKeys.map((key, idx) => (
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
                            )}
                          </div>
                        ) : signatureErrorMessage && (
                          <div>
                            <p className="text-theme-primary text-sm mb-2 font-mono text-xs bg-theme-input p-2 rounded">
                              {signatureErrorMessage}
                            </p>
                            {(() => {
                              // Fallback: Extract progress information (got X, want Y)
                              const gotMatch = signatureErrorMessage.match(/got\s+(\d+)/i);
                              const wantMatch = signatureErrorMessage.match(/want\s+(\d+)/i);
                              if (gotMatch && wantMatch) {
                                const got = parseInt(gotMatch[1], 10);
                                const want = parseInt(wantMatch[1], 10);
                                const remaining = want - got;
                                return (
                                  <p className="text-theme-primary text-sm mb-2">
                                    <strong>Progress:</strong> {got} of {want} signatures submitted 
                                    ({remaining} more {remaining === 1 ? 'signature' : 'signatures'} needed)
                                  </p>
                                );
                              }
                              return null;
                            })()}
                          </div>
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
                            <p className="text-theme-primary text-sm mb-2 font-mono text-xs bg-theme-input p-2 rounded">
                              {signatureErrorMessage}
                            </p>
                            {/* Show progress even for error status if it contains threshold info */}
                            {signatureProgress ? (
                              <div className="mt-3 space-y-3">
                                {/* Overall Progress */}
                                <div className="bg-theme-input rounded-lg p-3">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-theme-primary font-semibold">Overall Progress</span>
                                    <span className="text-yellow-500 font-bold">
                                      {signatureProgress.collected} / {signatureProgress.total}
                                    </span>
                                  </div>
                                  <div className="w-full bg-gray-700 rounded-full h-2.5 mb-2">
                                    <div 
                                      className="bg-yellow-500 h-2.5 rounded-full transition-all duration-300"
                                      style={{ width: `${(signatureProgress.collected / signatureProgress.total) * 100}%` }}
                                    ></div>
                                  </div>
                                  <p className="text-theme-primary text-xs">
                                    {signatureProgress.remaining} more {signatureProgress.remaining === 1 ? 'signature' : 'signatures'} required
                                  </p>
                                </div>

                                {/* Breakdown by Old/New Keys */}
                                <div className="grid grid-cols-2 gap-3">
                                  <div className="bg-theme-input rounded-lg p-3">
                                    <p className="text-theme-primary text-xs font-semibold mb-1">Old Keys</p>
                                    <p className="text-green-400 text-sm font-bold">
                                      {signatureProgress.oldCollected} collected
                                    </p>
                                    {signatureProgress.oldRemaining > 0 && (
                                      <p className="text-yellow-400 text-xs mt-1">
                                        {signatureProgress.oldRemaining} more needed
                                      </p>
                                    )}
                                  </div>
                                  <div className="bg-theme-input rounded-lg p-3">
                                    <p className="text-theme-primary text-xs font-semibold mb-1">New Keys</p>
                                    <p className="text-green-400 text-sm font-bold">
                                      {signatureProgress.newCollected} collected
                                    </p>
                                    {signatureProgress.newRemaining > 0 && (
                                      <p className="text-yellow-400 text-xs mt-1">
                                        {signatureProgress.newRemaining} more needed
                                      </p>
                                    )}
                                  </div>
                                </div>

                                {/* Signed Keys */}
                                {signatureProgress.oldKeysSigned.length > 0 && (
                                  <div className="bg-theme-input rounded-lg p-3">
                                    <p className="text-theme-primary text-xs font-semibold mb-2">✓ Old Keys Signed</p>
                                    <div className="flex flex-wrap gap-1">
                                      {signatureProgress.oldKeysSigned.map((key, idx) => (
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

                                {/* Missing Keys */}
                                {(signatureProgress.missingOldKeys.length > 0 || signatureProgress.missingNewKeys.length > 0) && (
                                  <div className="bg-theme-input rounded-lg p-3">
                                    <p className="text-theme-primary text-xs font-semibold mb-2">⚠ Missing Keys</p>
                                    {signatureProgress.missingOldKeys.length > 0 && (
                                      <div className="mb-2">
                                        <p className="text-yellow-400 text-xs mb-1">Old Keys:</p>
                                        <div className="flex flex-wrap gap-1">
                                          {signatureProgress.missingOldKeys.map((key, idx) => (
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
                                    {signatureProgress.missingNewKeys.length > 0 && (
                                      <div>
                                        <p className="text-yellow-400 text-xs mb-1">New Keys:</p>
                                        <div className="flex flex-wrap gap-1">
                                          {signatureProgress.missingNewKeys.map((key, idx) => (
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
                                )}
                              </div>
                            ) : signatureErrorMessage && (signatureErrorMessage.includes('not enough signatures') || signatureErrorMessage.includes('threshold not reached')) && (
                              <div className="mt-3 p-3 bg-yellow-500 bg-opacity-10 border border-yellow-500 rounded-lg">
                                <p className="text-yellow-500 text-sm font-semibold mb-2">Threshold not reached</p>
                                <p className="text-theme-primary text-sm">
                                  This is expected - continue submitting more signatures until the threshold is met.
                                </p>
                              </div>
                            )}
                          </>
                        )}
                        <p className="text-theme-primary text-sm mt-3">
                          {signatureProgress || (signatureErrorMessage && (signatureErrorMessage.includes('not enough signatures') || signatureErrorMessage.includes('threshold not reached')))
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
                          Root keys rotation has been completed successfully. All required signatures have been submitted and the threshold has been met. Now you can check "Root-Meta-Update" task in the history to see the result.
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
                Step 4: Promote the new keys
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
                      It re-verifies the repository and reconciles the keystore against it: the new root keys go from pending to
                      active, the keys they replaced become retired, and thresholds are re-read. Nothing is promoted until the
                      repository actually serves them, so a submission that never landed cannot leave the keystore out of sync.
                      The retired root private keys stay on disk until you run <code className="bg-theme-input px-1 rounded">tuf-kms keys prune</code>.
                    </p>
                  </div>
                </div>
              </div>
        </>
      )}
    </div>
  );
};
