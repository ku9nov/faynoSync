import React from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ModalFeedback } from './ModalFeedback';
import { MODAL_CLOSE, MODAL_HEADER, MODAL_OVERLAY, MODAL_SURFACE, MODAL_TITLE } from './ui';

interface BaseModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  isLoading?: boolean;
  isSuccess?: boolean;
  successMessage?: string;
  error?: { error: string; details?: string } | null;
  setError?: (error: { error: string; details?: string } | null) => void;
  className?: string;
}

export const BaseModal: React.FC<BaseModalProps> = ({
  title,
  onClose,
  children,
  isLoading = false,
  isSuccess = false,
  successMessage = 'Operation completed successfully!',
  error = null,
  setError,
  className = '',
}) => {
  const backdropProps = useBackdropClose(onClose);

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} ${className}`}>
        <ModalFeedback
          isLoading={isLoading}
          isSuccess={isSuccess}
          successMessage={successMessage}
          error={error}
          setError={setError}
        />
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>{title}</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
};
