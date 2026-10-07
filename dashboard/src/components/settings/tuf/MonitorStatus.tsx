import React from 'react';
import { StepStatus, TaskData } from '@/components/settings/tuf/types';
import { getStatusColor, getStatusIcon, getTaskStateColor } from '@/components/settings/tuf/utils';

interface MonitorStatusProps {
  selectedApp: string;
  step3Status: StepStatus;
  bootstrapStatus: TaskData | null;
  bootstrapTaskId: string;
  showBootstrapRecovery: boolean;
  bootstrapRecoveryLoading: boolean;
  onCheckBootstrapStatus: () => void;
  onRecoverBootstrapState: () => void;
}

export const MonitorStatus: React.FC<MonitorStatusProps> = ({
  selectedApp,
  step3Status,
  bootstrapStatus,
  // bootstrapTaskId,
  showBootstrapRecovery,
  bootstrapRecoveryLoading,
  onCheckBootstrapStatus,
  onRecoverBootstrapState,
}) => {
  if (!selectedApp) {
    return null;
  }

  return (
    <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold text-theme-primary">
          Monitor Status
        </h2>
        <div className={`flex items-center ${getStatusColor(step3Status)}`}>
          <i className={`fas ${getStatusIcon(step3Status)} mr-2`}></i>
          <span className="text-sm capitalize">{step3Status.replace('-', ' ')}</span>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex gap-2">
          <button
            onClick={onCheckBootstrapStatus}
            disabled={!selectedApp}
            className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <i className="fas fa-sync mr-2"></i>
            Check Bootstrap Status
          </button>
          {showBootstrapRecovery && (
            <div className="flex items-center gap-2">
              <button
                onClick={onRecoverBootstrapState}
                disabled={bootstrapRecoveryLoading || !selectedApp}
                className="bg-amber-600 text-white px-4 py-2 rounded-lg hover:bg-amber-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <i className={`fas ${bootstrapRecoveryLoading ? 'fa-spinner fa-spin' : 'fa-wrench'} mr-2`}></i>
                {bootstrapRecoveryLoading ? 'Recovering...' : 'Recovery'}
              </button>
              <span
                className="text-amber-400 text-sm cursor-help"
                title="Looks like Redis bootstrap data was lost. Recovery from metadata is recommended."
                aria-label="Recovery recommendation info"
              >
                <i className="fas fa-info-circle"></i>
              </span>
            </div>
          )}
          {/* <button
            onClick={onCheckTufTasks}
            disabled={!bootstrapTaskId && !bootstrapStatus?.task_id}
            className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <i className="fas fa-tasks mr-2"></i>
            Check TUF Task
          </button> */}
        </div>

        {bootstrapStatus ? (
          <div className="p-4 bg-theme-input rounded-lg border border-theme">
            <h3 className="text-theme-primary font-semibold mb-2">Bootstrap Status</h3>
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-theme-primary opacity-70">Task ID: </span>
                <span className="text-theme-primary font-mono">{bootstrapStatus.task_id}</span>
              </div>
              <div>
                <span className="text-theme-primary opacity-70">State: </span>
                <span className={getTaskStateColor(bootstrapStatus.state)}>
                  {bootstrapStatus.state}
                </span>
              </div>
              {bootstrapStatus.result && (
                <>
                  <div className="text-theme-primary">{bootstrapStatus.result.message}</div>
                  {bootstrapStatus.result.last_update && (
                    <div>
                      <span className="text-theme-primary opacity-70">Last Update: </span>
                      <span className="text-theme-primary">
                        {new Date(bootstrapStatus.result.last_update).toLocaleString()}
                      </span>
                    </div>
                  )}
                  {bootstrapStatus.result.error && (
                    <div className="text-red-500">{bootstrapStatus.result.error}</div>
                  )}
                </>
              )}
            </div>
          </div>
        ) : (
          <div className="p-4 bg-theme-input rounded-lg border border-theme">
            <h3 className="text-theme-primary font-semibold mb-2">Bootstrap Status</h3>
            <div className="text-sm text-theme-primary opacity-70">
              <i className="fas fa-info-circle mr-2"></i>
              Bootstrap has not been started yet. System is available for bootstrap.
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
