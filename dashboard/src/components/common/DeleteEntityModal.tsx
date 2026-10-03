import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { AxiosError } from 'axios';
import { ModalFeedback } from './ModalFeedback';
import {
  BTN_DANGER,
  BTN_GHOST,
  FIELD_INPUT,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
} from './ui';

interface DeleteEntityModalProps {
  entityName: string;
  entityType: 'platform' | 'channel' | 'architecture' | 'app' | 'version' | 'artifact';
  onClose: () => void;
  onConfirm: () => Promise<void>;
  confirmationValue?: string;
}

interface ErrorResponse {
  error: string;
  details?: string;
}

export const DeleteEntityModal: React.FC<DeleteEntityModalProps> = ({
  entityName,
  entityType,
  onClose,
  onConfirm,
  confirmationValue,
}) => {
  const [confirmationText, setConfirmationText] = useState('');
  const [error, setError] = useState<{ error: string; details?: string } | null>(null);

  const getConfirmationMessage = () => {
    switch (entityType) {
      case 'platform':
        return `To delete platform "${entityName}" please enter its name:`;
      case 'channel':
        return `To delete channel "${entityName}" please enter its name:`;
      case 'architecture':
        return `To delete architecture "${entityName}" please enter its name:`;
      case 'app':
        return `To delete application "${entityName}" please enter its name:`;
      case 'version':
        return `To confirm deletion of application version "${entityName}", please enter its current version:`;
      case 'artifact':
        return `To delete artifact please enter this ${entityName}:`;
      default:
        return `To delete ${entityType} "${entityName}" please enter its name:`;
    }
  };

  const getPlaceholder = () => {
    switch (entityType) {
      case 'platform':
        return 'Enter platform name';
      case 'channel':
        return 'Enter channel name';
      case 'architecture':
        return 'Enter architecture name';
      case 'app':
        return 'Enter application name';
      case 'version':
        return 'Enter current version';
      case 'artifact':
        return 'Enter platform/arch';
      default:
        return `Enter ${entityType} name`;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const expectedValue = confirmationValue || entityName;
    if (confirmationText === expectedValue) {
      try {
        await onConfirm();
      } catch (err) {
        const axiosError = err as AxiosError<ErrorResponse>;
        if (axiosError.response?.data) {
          setError({
            error: axiosError.response.data.error || 'Failed to delete',
            details: axiosError.response.data.details
          });
        } else {
          setError({
            error: 'Failed to delete',
            details: axiosError.message
          });
        }
      }
    }
  };

  const backdropProps = useBackdropClose(onClose);

  return (
    <>
      <ModalFeedback error={error} setError={setError} />
      <div className={MODAL_OVERLAY} {...backdropProps}>
        <div className={`${MODAL_SURFACE} w-96`}>
          <div className={MODAL_HEADER}>
            <h2 className={MODAL_TITLE}>Delete confirmation</h2>
            <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <p className="mb-4 flex items-start gap-3 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-3 text-sm text-red-200">
            <i className="fas fa-exclamation-triangle mt-0.5"></i>
            <span>{getConfirmationMessage()}</span>
          </p>
          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <input
                type="text"
                value={confirmationText}
                onChange={(e) => setConfirmationText(e.target.value)}
                className={FIELD_INPUT}
                placeholder={getPlaceholder()}
              />
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" onClick={onClose} className={BTN_GHOST}>
                Cancel
              </button>
              <button
                type="submit"
                disabled={confirmationText !== (confirmationValue || entityName)}
                className={BTN_DANGER}
              >
                Delete
              </button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}; 