import React, { useState } from 'react';

interface ModalFeedbackProps {
  isLoading?: boolean;
  loadingMessage?: string;
  isSuccess?: boolean;
  successMessage?: string;
  error?: { error: string; details?: string } | null;
  setError?: (error: { error: string; details?: string } | null) => void;
}

const TOAST = 'fixed top-4 right-4 rounded-lg border bg-black/85 px-5 py-3 shadow-xl animate-fade-in';

// The loading / success / error toasts every modal shipped its own copy of.
export const ModalFeedback: React.FC<ModalFeedbackProps> = ({
  isLoading = false,
  loadingMessage = 'Processing...',
  isSuccess = false,
  successMessage = 'Operation completed successfully!',
  error = null,
  setError,
}) => {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <>
      {isLoading && (
        <div className={`${TOAST} z-[12000] flex items-center gap-3 border-white/20 text-theme-primary`}>
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"></div>
          <span>{loadingMessage}</span>
        </div>
      )}
      {isSuccess && (
        <div className={`${TOAST} z-[12000] flex items-center gap-3 border-green-500/45 text-green-300`}>
          <i className="fas fa-check"></i>
          <span>{successMessage}</span>
        </div>
      )}
      {error && (
        <div className={`${TOAST} z-[12001] border-red-500/50 text-red-200`}>
          <div className="flex items-center gap-3">
            <i className="fas fa-exclamation-circle"></i>
            <span>{error.error}</span>
            {error.details && (
              <button
                type="button"
                onClick={() => setShowDetails(!showDetails)}
                className="ml-1 rounded p-1 text-red-200 transition-colors hover:bg-white/10"
                aria-label={showDetails ? 'Hide details' : 'Show details'}
              >
                <i className={`fas fa-chevron-down transition-transform ${showDetails ? 'rotate-180' : ''}`}></i>
              </button>
            )}
            {setError && (
              <button
                type="button"
                onClick={() => setError(null)}
                className="rounded p-1 text-red-200 transition-colors hover:bg-white/10"
                aria-label="Dismiss error"
              >
                <i className="fas fa-times"></i>
              </button>
            )}
          </div>
          {showDetails && error.details && (
            <div className="mt-2 rounded border border-red-500/30 bg-black/50 p-2 font-mono text-xs text-red-100">
              {error.details}
            </div>
          )}
        </div>
      )}
    </>
  );
};
