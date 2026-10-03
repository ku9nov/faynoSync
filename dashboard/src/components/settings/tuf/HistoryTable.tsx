import React, { useState } from 'react';
import { TufHistoryEntry } from '@/components/settings/tuf/types';

interface HistoryProps {
  selectedApp: string | null;
  history: TufHistoryEntry[];
  onCheckTask: (taskId: string, options?: { silent?: boolean }) => void;
  onClearHistory: () => void;
}

export const HistoryTable: React.FC<HistoryProps> = ({
  selectedApp,
  history,
  onCheckTask,
  onClearHistory,
}) => {
  const [showHistory, setShowHistory] = useState(false);
  const [selectedResultEntry, setSelectedResultEntry] = useState<TufHistoryEntry | null>(null);
  const autoCheckedTaskIdsRef = React.useRef<Set<string>>(new Set());

  // Auto-open history when app is selected
  React.useEffect(() => {
    if (selectedApp) {
      setShowHistory(true);
    }
  }, [selectedApp]);

  const isHistoryVisible = !selectedApp || showHistory;
  const canCheckTask = (entry: TufHistoryEntry) => Boolean(entry.taskId);
  const canViewResult = (entry: TufHistoryEntry) => entry.result !== undefined;

  const formatResultForDisplay = (result: TufHistoryEntry['result']) => {
    if (result === undefined) {
      return 'No result data available.';
    }

    try {
      return JSON.stringify(result, null, 2);
    } catch {
      return String(result);
    }
  };

  const renderActions = (entry: TufHistoryEntry) => {
    const canCheck = canCheckTask(entry);
    const canShowResult = canViewResult(entry);

    if (!canCheck && !canShowResult) {
      return <span className="text-theme-primary opacity-50 text-sm">-</span>;
    }

    return (
      <div className="flex items-center gap-3">
        {canCheck && (
          <button
            onClick={() => onCheckTask(entry.taskId!)}
            className="text-theme-primary hover:text-theme-button-primary text-sm transition-colors"
            title="Check task status"
          >
            <i className="fas fa-sync mr-1"></i>
            Check
          </button>
        )}
        {canShowResult && (
          <button
            onClick={() => setSelectedResultEntry(entry)}
            className="text-theme-primary hover:text-theme-button-primary text-sm transition-colors"
            title="View task result"
          >
            <i className="fas fa-file-code mr-1"></i>
            Result
          </button>
        )}
      </div>
    );
  };

  const renderResultModal = () => {
    if (!selectedResultEntry) {
      return null;
    }

    return (
      <div
        className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
        onClick={() => setSelectedResultEntry(null)}
      >
        <div
          className="bg-theme-card border border-theme-card-hover rounded-lg w-full max-w-3xl max-h-[85vh] overflow-hidden"
          onClick={(event) => event.stopPropagation()}
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-theme-card-hover">
            <div>
              <h3 className="text-theme-primary font-bold">Task Result</h3>
              <div className="text-xs text-theme-primary opacity-70 mt-1">
                {selectedResultEntry.operation} - {selectedResultEntry.taskId || 'No task ID'}
              </div>
            </div>
            <button
              onClick={() => setSelectedResultEntry(null)}
              className="text-theme-primary hover:text-theme-button-primary transition-colors"
              title="Close"
            >
              <i className="fas fa-times"></i>
            </button>
          </div>
          <div className="p-4 overflow-auto max-h-[calc(85vh-76px)]">
            <pre className="text-xs text-theme-primary whitespace-pre-wrap break-words font-mono bg-theme-input border border-theme rounded-lg p-3">
              {formatResultForDisplay(selectedResultEntry.result)}
            </pre>
          </div>
        </div>
      </div>
    );
  };

  React.useEffect(() => {
    if (!isHistoryVisible) {
      return;
    }

    const pendingTaskIds = history
      .filter((entry) => entry.status === 'pending' && entry.taskId)
      .map((entry) => entry.taskId as string);

    if (pendingTaskIds.length === 0) {
      return;
    }

    pendingTaskIds.forEach((taskId) => {
      if (autoCheckedTaskIdsRef.current.has(taskId)) {
        return;
      }

      autoCheckedTaskIdsRef.current.add(taskId);
      onCheckTask(taskId, { silent: true });
    });
  }, [history, isHistoryVisible, onCheckTask]);

  // Show history when no app is selected (full view)
  if (!selectedApp) {
    return (
      <>
        <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
          <h2 className="text-lg font-bold text-theme-primary mb-4">History</h2>
          {history.length === 0 ? (
            <p className="text-theme-primary opacity-70 text-center py-4">No history yet</p>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-theme-card-hover">
                      <th className="text-left py-2 px-2 text-theme-primary">Date</th>
                      <th className="text-left py-2 px-2 text-theme-primary">App</th>
                      <th className="text-left py-2 px-2 text-theme-primary">Operation</th>
                      <th className="text-left py-2 px-2 text-theme-primary">Status</th>
                      <th className="text-left py-2 px-2 text-theme-primary">Task ID</th>
                      <th className="text-left py-2 px-2 text-theme-primary">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((entry) => (
                      <tr key={entry.id} className="border-b border-theme-card-hover">
                        <td className="py-2 px-2 text-theme-primary">
                          {new Date(entry.timestamp).toLocaleString()}
                        </td>
                        <td className="py-2 px-2 text-theme-primary">{entry.appName}</td>
                        <td className="py-2 px-2 text-theme-primary capitalize">
                          {entry.operation}
                        </td>
                        <td className="py-2 px-2">
                          <span
                            className={
                              entry.status === 'success'
                                ? 'text-green-500'
                                : entry.status === 'pending'
                                ? 'text-yellow-500'
                                : 'text-red-500'
                            }
                          >
                            {entry.status === 'success' ? (
                              <i className="fas fa-check-circle mr-1"></i>
                            ) : entry.status === 'pending' ? (
                              <i className="fas fa-clock mr-1"></i>
                            ) : (
                              <i className="fas fa-times-circle mr-1"></i>
                            )}
                            {entry.status}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-theme-primary font-mono text-xs">
                          {entry.taskId || '-'}
                        </td>
                        <td className="py-2 px-2">{renderActions(entry)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="mt-4 flex justify-end">
                <button
                  onClick={onClearHistory}
                  className="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition-colors"
                >
                  <i className="fas fa-trash mr-2"></i>
                  Clear History
                </button>
              </div>
            </>
          )}
        </div>
        {renderResultModal()}
      </>
    );
  }

  // Show collapsible history when app is selected
  return (
    <>
      <div className="bg-theme-card p-6 rounded-lg border border-theme-card-hover">
        <button
          onClick={() => setShowHistory(!showHistory)}
          className="flex items-center justify-between w-full text-theme-primary hover:text-theme-button-primary"
        >
          <h2 className="text-lg font-bold">History</h2>
          <i className={`fas fa-chevron-${showHistory ? 'up' : 'down'}`}></i>
        </button>

        {showHistory && (
          <div className="mt-4">
            {history.length === 0 ? (
              <p className="text-theme-primary opacity-70 text-center py-4">No history yet</p>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-theme-card-hover">
                        <th className="text-left py-2 px-2 text-theme-primary">Date</th>
                        <th className="text-left py-2 px-2 text-theme-primary">App</th>
                        <th className="text-left py-2 px-2 text-theme-primary">Operation</th>
                        <th className="text-left py-2 px-2 text-theme-primary">Status</th>
                        <th className="text-left py-2 px-2 text-theme-primary">Task ID</th>
                        <th className="text-left py-2 px-2 text-theme-primary">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((entry) => (
                        <tr key={entry.id} className="border-b border-theme-card-hover">
                          <td className="py-2 px-2 text-theme-primary">
                            {new Date(entry.timestamp).toLocaleString()}
                          </td>
                          <td className="py-2 px-2 text-theme-primary">{entry.appName}</td>
                          <td className="py-2 px-2 text-theme-primary capitalize">
                            {entry.operation}
                          </td>
                          <td className="py-2 px-2">
                            <span
                              className={
                                entry.status === 'success'
                                  ? 'text-green-500'
                                  : entry.status === 'pending'
                                  ? 'text-yellow-500'
                                  : 'text-red-500'
                              }
                            >
                              {entry.status === 'success' ? (
                                <i className="fas fa-check-circle mr-1"></i>
                              ) : entry.status === 'pending' ? (
                                <i className="fas fa-clock mr-1"></i>
                              ) : (
                                <i className="fas fa-times-circle mr-1"></i>
                              )}
                              {entry.status}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-theme-primary font-mono text-xs">
                            {entry.taskId || '-'}
                          </td>
                          <td className="py-2 px-2">{renderActions(entry)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-4 flex justify-end">
                  <button
                    onClick={onClearHistory}
                    className="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition-colors"
                  >
                    <i className="fas fa-trash mr-2"></i>
                    Clear History
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </div>
      {renderResultModal()}
    </>
  );
};
