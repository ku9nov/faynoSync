import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ModalFeedback } from '@/components/common/ModalFeedback';
import {
  BTN_DANGER,
  BTN_GHOST,
  FIELD_INPUT,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
} from '@/components/common/ui';

interface DeleteUserConfirmationModalProps {
  userId: string;
  username: string;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteUserConfirmationModal: React.FC<DeleteUserConfirmationModalProps> = ({
  username,
  isOpen,
  onClose,
  onConfirm,
}) => {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmationText, setConfirmationText] = useState('');

  const handleConfirm = async () => {
    if (confirmationText !== username) return;
    
    setIsDeleting(true);
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to delete user');
    } finally {
      setIsDeleting(false);
    }
  };

  const backdropProps = useBackdropClose(onClose);

  if (!isOpen) return null;

  return (
    <>
      <ModalFeedback error={error ? { error } : null} setError={() => setError(null)} />
      <div className={`${MODAL_OVERLAY} z-[10000] min-h-screen overflow-y-auto p-4`} {...backdropProps}>
        <div className={`${MODAL_SURFACE} w-full max-w-md max-h-[90vh]`}>
          <div className={MODAL_HEADER}>
            <h2 className={MODAL_TITLE}>Delete user</h2>
            <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <p className="mb-4 flex items-start gap-3 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-3 text-sm text-red-200">
            <i className="fas fa-exclamation-triangle mt-0.5"></i>
            <span>To delete user "{username}" please enter their username:</span>
          </p>
          <div className="mb-6">
            <input
              type="text"
              value={confirmationText}
              onChange={(e) => setConfirmationText(e.target.value)}
              className={FIELD_INPUT}
              placeholder="Enter username"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={BTN_GHOST}>
              Cancel
            </button>
            <button
              type="button"
              onClick={handleConfirm}
              disabled={confirmationText !== username || isDeleting}
              className={`${BTN_DANGER} inline-flex items-center gap-2`}
            >
              {isDeleting ? (
                <>
                  <i className="fas fa-spinner fa-spin"></i>
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
