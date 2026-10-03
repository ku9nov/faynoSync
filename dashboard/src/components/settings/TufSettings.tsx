import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useAppsQuery, AppListItem } from '@/hooks/use-query/useAppsQuery';
import { useToast } from '@/hooks/useToast';
import axiosInstance from '@/config/axios';
import { StepStatus, TaskData, TufHistoryEntry, TufConfig } from '@/components/settings/tuf/types';
import { loadHistoryFromStorage, saveToHistory, updateHistoryStatus, clearHistory } from '@/components/settings/tuf/history';
import { AppSelection } from '@/components/settings/tuf/AppSelection';
import { GenerateKeysOffline } from '@/components/settings/tuf/GenerateKeysOffline';
import { Bootstrap } from '@/components/settings/tuf/Bootstrap';
import { MonitorStatus } from '@/components/settings/tuf/MonitorStatus';
import { Config } from '@/components/settings/tuf/Config';
import { RenewRoot } from '@/components/settings/tuf/RenewRoot';
import { RotateRootKeys } from '@/components/settings/tuf/RotateRootKeys';
import { RotateRoleKeys } from '@/components/settings/tuf/RotateRoleKeys';
import { RotateDelegatedKeys } from '@/components/settings/tuf/RotateDelegatedKeys';
import { HistoryTable } from '@/components/settings/tuf/HistoryTable';

export const TufSettings: React.FC = () => {
  const { apps } = useAppsQuery();
  const { toastSuccess, toastError } = useToast();
  const [selectedApp, setSelectedApp] = useState<string>('');
  
  // Step 1: Generate TUF Root Keys
  const [step1Status, setStep1Status] = useState<StepStatus>('ready');
  const [generatedPayload, setGeneratedPayload] = useState<string>('');
  
  // Step 2: Start TUF Bootstrapping
  const [step2Status, setStep2Status] = useState<StepStatus>('waiting');
  const [bootstrapTaskId, setBootstrapTaskId] = useState<string>('');
  const [bootstrapLastUpdate, setBootstrapLastUpdate] = useState<string>('');
  
  // Step 3: Monitor Status
  const [step3Status, setStep3Status] = useState<StepStatus>('disabled');
  const [bootstrapStatus, setBootstrapStatus] = useState<TaskData | null>(null);
  const [showBootstrapRecovery, setShowBootstrapRecovery] = useState<boolean>(false);
  const [bootstrapRecoveryLoading, setBootstrapRecoveryLoading] = useState<boolean>(false);
  const [history, setHistory] = useState<TufHistoryEntry[]>([]);
  
  // Polling
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [lastChecked, setLastChecked] = useState<string>('');

  // Config section
  const [tufConfig, setTufConfig] = useState<TufConfig | null>(null);
  const [configLoading, setConfigLoading] = useState<boolean>(false);
  const [configUpdating, setConfigUpdating] = useState<boolean>(false);
  const [editableExpiration, setEditableExpiration] = useState({
    targets: 100,
    snapshot: 50,
    timestamp: 20,
  });
  const configLoadedRef = useRef<string>(''); // Track which app's config is loaded

  // Check if bootstrap is successful (computed value)
  const isBootstrapSuccess = bootstrapStatus?.state === 'SUCCESS';

  // Load history from localStorage
  useEffect(() => {
    const loadedHistory = loadHistoryFromStorage();
    setHistory(loadedHistory);
  }, []);

  // Update step statuses based on state
  useEffect(() => {
    console.log('[TufSettings] useEffect step statuses:', {
      selectedApp,
      step1Status,
      step2Status,
      bootstrapTaskId,
    });

    if (!selectedApp) {
      setStep1Status('ready');
      setStep2Status('waiting');
      setStep3Status('disabled');
      return;
    }

    // Step 2 should be available whenever an app is selected
    // User can use custom payload even without generating keys (Step 1)
    // Don't overwrite bootstrap states (error, success, in-progress)
    if (step2Status !== 'error' && step2Status !== 'success' && step2Status !== 'in-progress') {
      console.log('[TufSettings] Setting step2Status to ready (app selected, can use custom payload)');
      setStep2Status('ready');
    } else {
      console.log('[TufSettings] Keeping step2Status as', step2Status, '(already in bootstrap state)');
    }

    if (bootstrapTaskId) {
      setStep3Status('ready');
    }
  }, [selectedApp, step1Status, bootstrapTaskId]);

  // Auto-check bootstrap status when app is selected
  useEffect(() => {
    if (selectedApp) {
      checkBootstrapStatus();
    }
  }, [selectedApp]);

  // Polling for bootstrap status - only when bootstrap is in progress, not when already successful
  useEffect(() => {
    // Only poll if bootstrap is in progress (PENDING state) and not yet successful
    const shouldPoll = selectedApp && 
      bootstrapStatus?.state === 'PENDING' && 
      !isBootstrapSuccess;
    
    if (shouldPoll) {
      pollingIntervalRef.current = setInterval(() => {
        checkBootstrapStatus();
        setLastChecked(new Date().toLocaleTimeString());
      }, 5000);
    } else {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    }

    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedApp, bootstrapStatus?.state, isBootstrapSuccess]); // checkBootstrapStatus is stable

  // API functions
  const startBootstrap = async (payload: string) => {
    console.log('[TufSettings] startBootstrap called, setting step2Status to in-progress');
    setStep2Status('in-progress');
    
    try {
      // Parse payload to ensure it's valid JSON
      const payloadData = JSON.parse(payload);
      
      const response = await axiosInstance.post('/tuf/v1/bootstrap', payloadData);
      
      // Extract task_id and last_update from response
      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }
      
      const taskId = responseData.task_id;
      const lastUpdate = responseData.last_update;
      
      if (!taskId) {
        throw new Error('Invalid response: missing task_id');
      }
      
      setBootstrapTaskId(taskId);
      setBootstrapLastUpdate(lastUpdate || new Date().toISOString());
      console.log('[TufSettings] Bootstrap started successfully, setting step2Status to success');
      setStep2Status('success');
      
      toastSuccess('TUF bootstrap started successfully!');
      
      // Save with initial status, will be updated when we check the actual status
      setHistory(prevHistory => saveToHistory({
        timestamp: lastUpdate || new Date().toISOString(),
        appName: selectedApp,
        operation: 'bootstrap',
        status: 'pending', // Will be updated when we check actual status via API
        taskId: taskId,
      }, prevHistory));
      
      // Immediately check the task status to update history with real status
      setTimeout(() => {
        checkTufTasks(taskId);
      }, 1000);
    } catch (error: any) {
      console.error('Failed to start TUF bootstrap:', error);
      console.log('[TufSettings] Bootstrap failed, setting step2Status to error');
      setStep2Status('error');
      
      const errorMessage = error.response?.data?.message || error.message || 'Failed to start TUF bootstrap';
      toastError(errorMessage);
      
      setHistory(prevHistory => saveToHistory({
        timestamp: new Date().toISOString(),
        appName: selectedApp,
        operation: 'bootstrap',
        status: 'failed',
      }, prevHistory));
    }
  };

  const checkBootstrapStatus = async () => {
    if (!selectedApp) return;
    
    try {
      const response = await axiosInstance.get(`/tuf/v1/bootstrap?appName=${encodeURIComponent(selectedApp)}`);
      
      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }
      
      // Check if bootstrap is not started yet
      if (responseData.bootstrap === false) {
        console.log('[TufSettings] checkBootstrapStatus: bootstrap is false');
        setBootstrapStatus(null);
        setShowBootstrapRecovery(false);
        setBootstrapTaskId('');
        setBootstrapLastUpdate('');
        // Only set to 'ready' if not already in a bootstrap state (error, success, in-progress)
        if (step2Status !== 'error' && step2Status !== 'success' && step2Status !== 'in-progress') {
          console.log('[TufSettings] checkBootstrapStatus: setting step2Status to ready (bootstrap not started)');
          setStep2Status('ready');
        } else {
          console.log('[TufSettings] checkBootstrapStatus: keeping step2Status as', step2Status, '(already in bootstrap state)');
        }
        setStep3Status('disabled');
        return;
      }
      
      // Check if bootstrap is already completed (bootstrap: true, state: null)
      if (responseData.bootstrap === true && responseData.state === null) {
        const hasBootstrapId = Boolean(String(responseData.id ?? '').trim());
        const hasRedisBootstrapLock = Boolean(String(responseData.redis_locks?.bootstrap_lock ?? '').trim());
        setShowBootstrapRecovery(!hasBootstrapId || !hasRedisBootstrapLock);

        // Bootstrap completed successfully
        const statusData: TaskData = {
          task_id: responseData.id || '',
          state: 'SUCCESS',
          result: {
            message: response.data?.message || 'Bootstrap completed successfully',
            status: true,
            task: 'bootstrap',
          },
        };
        
        setBootstrapStatus(statusData);
        
        // Update task_id if it wasn't set before
        if (!bootstrapTaskId && statusData.task_id) {
          setBootstrapTaskId(statusData.task_id);
        }
        
        setStep2Status('success');
        setStep3Status('ready');
        
        // Update history status for completed bootstrap
        if (statusData.task_id) {
          setHistory(prevHistory => updateHistoryStatus(statusData.task_id, statusData.state, prevHistory, statusData.result));
        }
        return;
      }
      
      // Bootstrap is in progress (has state: PENDING/SUCCESS/FAILURE)
      const statusData: TaskData = {
        task_id: responseData.task_id || responseData.id || '',
        state: responseData.state,
        result: responseData.result,
      };
      
      setBootstrapStatus(statusData);
      setShowBootstrapRecovery(false);
      
      // Update task_id if it wasn't set before
      if (!bootstrapTaskId && statusData.task_id) {
        setBootstrapTaskId(statusData.task_id);
      }
      
      // Update last_update if available
      if (responseData.result?.last_update) {
        setBootstrapLastUpdate(responseData.result.last_update);
      }
      
      // Update step statuses based on state
      if (statusData.state === 'SUCCESS') {
        console.log('[TufSettings] checkBootstrapStatus: state is SUCCESS, setting step2Status to success');
        setStep2Status('success');
        setStep3Status('ready');
      } else if (statusData.state === 'FAILURE') {
        console.log('[TufSettings] checkBootstrapStatus: state is FAILURE, setting step2Status to error');
        setStep2Status('error');
      } else if (statusData.state === 'PENDING') {
        console.log('[TufSettings] checkBootstrapStatus: state is PENDING, setting step2Status to in-progress');
        setStep2Status('in-progress');
      }
      
      // Update history status based on actual task state
      if (statusData.task_id) {
        setHistory(prevHistory => updateHistoryStatus(statusData.task_id, statusData.state, prevHistory, statusData.result));
      }
    } catch (error: any) {
      console.error('Failed to check bootstrap status:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to check bootstrap status';
      toastError(errorMessage);
    }
  };

  const recoverBootstrapState = async () => {
    if (!selectedApp) return;

    setBootstrapRecoveryLoading(true);
    try {
      const response = await axiosInstance.post('/tuf/v1/bootstrap/recovery', {
        appName: selectedApp,
      });

      const responseData = response.data?.data;
      const recoveryTaskId = responseData?.task_id;
      const recoveryLastUpdate = responseData?.last_update;
      const message = response.data?.message || 'Bootstrap recovery completed successfully.';
      toastSuccess(message);

      if (recoveryTaskId) {
        setHistory(prevHistory => saveToHistory({
          timestamp: recoveryLastUpdate || new Date().toISOString(),
          appName: selectedApp,
          operation: 'bootstrap-recovery',
          status: 'pending',
          taskId: recoveryTaskId,
        }, prevHistory));

        setTimeout(() => {
          checkTufTasks(recoveryTaskId, { silent: true });
        }, 1000);
      }

      await checkBootstrapStatus();
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to recover bootstrap state';
      toastError(errorMessage);
    } finally {
      setBootstrapRecoveryLoading(false);
    }
  };

  const checkTufTasks = async (taskId?: string, options?: { silent?: boolean }) => {
    // Use provided taskId, or bootstrapTaskId, or bootstrapStatus?.task_id
    const taskIdToUse = taskId || bootstrapTaskId || bootstrapStatus?.task_id;
    if (!taskIdToUse) {
      if (!options?.silent) {
        toastError('No task ID available. Please start bootstrap first or select a task from history.');
      }
      return;
    }
    
    try {
      const response = await axiosInstance.get(`/tuf/v1/task?task_id=${encodeURIComponent(taskIdToUse)}`);
      
      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }
      
      // Handle both single task and array of tasks
      const tasks: TaskData[] = Array.isArray(responseData) 
        ? responseData 
        : [responseData];
      
      // Update history status based on actual task state
      setHistory(prevHistory => {
        let updatedHistory = prevHistory;
        tasks.forEach(task => {
          if (task.task_id) {
            updatedHistory = updateHistoryStatus(task.task_id, task.state, updatedHistory, task.result);
          }
        });
        return updatedHistory;
      });
      
      if (!options?.silent) {
        toastSuccess('TUF task loaded successfully!');
      }
    } catch (error: any) {
      console.error('Failed to check TUF task:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to check TUF task';
      if (!options?.silent) {
        toastError(errorMessage);
      }
    }
  };

  const loadConfig = useCallback(async () => {
    if (!selectedApp) return;
    
    // Prevent multiple simultaneous requests for the same app
    if (configLoadedRef.current === selectedApp) {
      return;
    }
    
    setConfigLoading(true);
    configLoadedRef.current = selectedApp; // Mark as loading immediately to prevent duplicates
    try {
      const response = await axiosInstance.get(`/tuf/v1/config?appName=${encodeURIComponent(selectedApp)}`);
      
      const configData = response.data?.data;
      if (!configData) {
        throw new Error('Invalid response: missing data field');
      }
      
      setTufConfig(configData as TufConfig);
      
      // Set editable expiration values from config
      setEditableExpiration({
        targets: configData.targets_expiration || 100,
        snapshot: configData.snapshot_expiration || 50,
        timestamp: configData.timestamp_expiration || 20,
      });
    } catch (error: any) {
      console.error('Failed to load config:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to load config';
      toastError(errorMessage);
      configLoadedRef.current = ''; // Reset on error
    } finally {
      setConfigLoading(false);
    }
  }, [selectedApp]);

  // Load config when bootstrap is successful
  useEffect(() => {
    if (selectedApp && isBootstrapSuccess) {
      // Only load if config is not already loaded for this app
      if (configLoadedRef.current !== selectedApp) {
        loadConfig();
      }
    } else {
      setTufConfig(null);
      configLoadedRef.current = ''; // Reset when app changes or bootstrap not successful
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedApp, isBootstrapSuccess]); // loadConfig is stable, no need to include it

  const updateConfig = async (expiration: { targets: number; snapshot: number; timestamp: number }) => {
    if (!selectedApp) return;
    
    setConfigUpdating(true);
    try {
      const response = await axiosInstance.put(
        `/tuf/v1/config?appName=${encodeURIComponent(selectedApp)}`,
        {
          settings: {
            expiration: {
              targets: expiration.targets,
              snapshot: expiration.snapshot,
              timestamp: expiration.timestamp,
            },
          },
        }
      );
      
      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }
      
      const taskId = responseData.task_id;
      const lastUpdate = responseData.last_update;
      
      if (taskId) {
        toastSuccess('Config update submitted successfully!');
        
        setHistory(prevHistory => saveToHistory({
          timestamp: lastUpdate || new Date().toISOString(),
          appName: selectedApp,
          operation: 'update-config',
          status: 'pending',
          taskId: taskId,
        }, prevHistory));
        
        // Reload config to get updated values
        configLoadedRef.current = ''; // Reset to allow reload
        setTimeout(() => {
          loadConfig();
        }, 1000);
      } else {
        throw new Error('Invalid response: missing task_id');
      }
    } catch (error: any) {
      console.error('Failed to update config:', error);
      const errorMessage = error.response?.data?.message || error.message || 'Failed to update config';
      toastError(errorMessage);
      
      setHistory(prevHistory => saveToHistory({
        timestamp: new Date().toISOString(),
        appName: selectedApp,
        operation: 'update-config',
        status: 'failed',
      }, prevHistory));
    } finally {
      setConfigUpdating(false);
    }
  };

  // Handlers
  const handleAppChange = (appName: string) => {
    setSelectedApp(appName);
    // Reset states when app changes
    setStep1Status('ready');
    setStep2Status('waiting');
    setStep3Status('disabled');
    setGeneratedPayload('');
    setBootstrapTaskId('');
    setBootstrapStatus(null);
  };

  const handleResetStates = () => {
    setStep1Status('ready');
    setStep2Status('waiting');
    setStep3Status('disabled');
    setGeneratedPayload('');
    setBootstrapTaskId('');
    setBootstrapStatus(null);
  };

  const handleGeneratedPayload = (payload: string) => {
    setGeneratedPayload(payload);
  };

  const handleSaveToHistory = (entry: Omit<TufHistoryEntry, 'id'>) => {
    setHistory(prevHistory => saveToHistory(entry, prevHistory));
  };

  const handleClearHistory = () => {
    const clearedHistory = clearHistory();
    setHistory(clearedHistory);
  };

  const handleResetConfigLoaded = () => {
    configLoadedRef.current = '';
  };

  const updateMetadata = async (roles: string[]) => {
    if (!selectedApp) return;
    
    try {
      const response = await axiosInstance.post(
        `/tuf/v1/metadata/online?appName=${encodeURIComponent(selectedApp)}`,
        { roles }
      );
      
      const responseData = response.data?.data;
      if (!responseData) {
        throw new Error('Invalid response: missing data field');
      }
      
      const taskId = responseData.task_id;
      const lastUpdate = responseData.last_update;
      
      if (taskId) {
        const rolesText = roles.length === 0 ? 'all roles (timestamp, targets, snapshot)' : roles.join(', ');
        toastSuccess(`Metadata update submitted successfully for ${rolesText}!`);
        
        setHistory(prevHistory => saveToHistory({
          timestamp: lastUpdate || new Date().toISOString(),
          appName: selectedApp,
          operation: 'metadata-update',
          status: 'pending',
          taskId: taskId,
        }, prevHistory));
        
        // Check task status after a delay
        setTimeout(() => {
          checkTufTasks(taskId);
        }, 1000);
      } else {
        throw new Error('Invalid response: missing task_id');
      }
    } catch (error: any) {
      console.error('Failed to update metadata:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Failed to update metadata';
      toastError(errorMessage);
      
      setHistory(prevHistory => saveToHistory({
        timestamp: new Date().toISOString(),
        appName: selectedApp,
        operation: 'metadata-update',
        status: 'failed',
      }, prevHistory));
    }
  };

  return (
    <div className="space-y-6">
      {/* App Selection */}
      <AppSelection
        apps={apps as AppListItem[]}
        selectedApp={selectedApp}
        onAppChange={handleAppChange}
        onResetStates={handleResetStates}
      />

      {/* Step 1: Generate TUF Root Keys */}
      {/* <GenerateKeys
        selectedApp={selectedApp}
        isBootstrapSuccess={isBootstrapSuccess}
        onGeneratedPayload={handleGeneratedPayload}
        onStartBootstrap={startBootstrap}
        onSaveToHistory={handleSaveToHistory}
      /> */}

      {/* Step 1: Generate TUF Root Keys - Offline Mode */}
      <GenerateKeysOffline
        selectedApp={selectedApp}
        isBootstrapSuccess={isBootstrapSuccess}
        onGeneratedPayload={handleGeneratedPayload}
        onStartBootstrap={startBootstrap}
        onSaveToHistory={handleSaveToHistory}
      /> 

      {/* Step 2: Start TUF Bootstrapping */}
      <Bootstrap
        selectedApp={selectedApp}
        isBootstrapSuccess={isBootstrapSuccess}
        generatedPayload={generatedPayload}
        step2Status={step2Status}
        bootstrapTaskId={bootstrapTaskId}
        bootstrapLastUpdate={bootstrapLastUpdate}
        bootstrapStatus={bootstrapStatus}
        lastChecked={lastChecked}
        onStartBootstrap={startBootstrap}
      />

      {/* Monitor Status */}
      <MonitorStatus
        selectedApp={selectedApp}
        step3Status={step3Status}
        bootstrapStatus={bootstrapStatus}
        bootstrapTaskId={bootstrapTaskId}
        showBootstrapRecovery={showBootstrapRecovery}
        bootstrapRecoveryLoading={bootstrapRecoveryLoading}
        onCheckBootstrapStatus={checkBootstrapStatus}
        onRecoverBootstrapState={recoverBootstrapState}
      />

      {/* Update Section */}
      {selectedApp && isBootstrapSuccess && (
        <div className="rounded-lg border border-theme p-4">
          <div className="mb-4">
            <h2 className="text-xl font-bold text-theme-primary">Update</h2>
            <p className="mt-1 text-sm text-theme-primary opacity-70">
              Change the TUF settings, refresh the online metadata and push the root expiry date out. Nothing here
              replaces a key — the key set stays exactly as it is.
            </p>
          </div>
          <div className="space-y-4">
            <Config
              selectedApp={selectedApp}
              isBootstrapSuccess={isBootstrapSuccess}
              tufConfig={tufConfig}
              configLoading={configLoading}
              configUpdating={configUpdating}
              editableExpiration={editableExpiration}
              onLoadConfig={loadConfig}
              onUpdateConfig={updateConfig}
              onResetConfigLoaded={handleResetConfigLoaded}
              onUpdateMetadata={updateMetadata}
            />

            <RenewRoot
              selectedApp={selectedApp}
              isBootstrapSuccess={isBootstrapSuccess}
              onSaveToHistory={handleSaveToHistory}
              onCheckTufTasks={checkTufTasks}
            />
          </div>
        </div>
      )}

      {/* Key Rotation Section */}
      {selectedApp && isBootstrapSuccess && (
        <div className="rounded-lg border border-theme p-4">
          <div className="mb-4">
            <h2 className="text-xl font-bold text-theme-primary">Rotation</h2>
            <p className="mt-1 text-sm text-theme-primary opacity-70">
              Replace the keys behind a role. Use this when a key is compromised or has to change hands — not to move an
              expiry date.
            </p>
          </div>
          <div className="mb-4 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900 dark:border-blue-400/30 dark:bg-blue-500/10 dark:text-blue-100">
            <p className="font-semibold">About key rotation workflow</p>
            <p className="mt-2">
              The keys and the signing stay on your machine; this dashboard only submits what you paste into it.
              The <code className="rounded bg-blue-500/10 px-1">tuf-kms</code> command line tool does the crypto against its own
              keystore, and every rotation below follows the same shape: run one command, then paste the files it writes.
            </p>
            <p className="mt-2">
              Each run replaces the contents of <code className="rounded bg-blue-500/10 px-1">out/</code>, so there is nothing to
              clean up by hand — but for the same reason, finish one rotation before starting another, or the files you have not
              submitted yet are gone. A rotation is finished when the dashboard reports it and
              <code className="rounded bg-blue-500/10 px-1 ml-1">tuf-kms fetch</code> has promoted the new keys.
            </p>
            <p className="mt-2">
              If you are an experienced TUF user, you do not have to use tuf-kms for key rotation.
              You can prepare metadata and signatures yourself and submit them here directly.
            </p>
          </div>
          <div className="space-y-4">
            <RotateRootKeys
              selectedApp={selectedApp}
              isBootstrapSuccess={isBootstrapSuccess}
              onSaveToHistory={handleSaveToHistory}
              onCheckTufTasks={checkTufTasks}
            />

            <RotateRoleKeys
              selectedApp={selectedApp}
              isBootstrapSuccess={isBootstrapSuccess}
              onSaveToHistory={handleSaveToHistory}
              onCheckTufTasks={checkTufTasks}
              onUpdateMetadata={updateMetadata}
            />

            <RotateDelegatedKeys
              selectedApp={selectedApp}
              isBootstrapSuccess={isBootstrapSuccess}
              onSaveToHistory={handleSaveToHistory}
              onCheckTufTasks={checkTufTasks}
            />
          </div>
        </div>
      )}

      {/* History - Show last */}
      <HistoryTable
        selectedApp={selectedApp}
        history={history}
        onCheckTask={checkTufTasks}
        onClearHistory={handleClearHistory}
      />
    </div>
  );
};
