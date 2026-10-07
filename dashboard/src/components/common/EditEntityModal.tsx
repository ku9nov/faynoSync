import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { AxiosError } from 'axios';
import { ModalFeedback } from './ModalFeedback';
import {
  BTN_GHOST,
  BTN_PRIMARY,
  FIELD_INPUT,
  FIELD_LABEL,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
} from './ui';

interface EditModalProps {
  title: string;
  label: string;
  initialName: string;
  onClose: () => void;
  onUpdate: (newName: string) => Promise<void>;
}

interface ErrorResponse {
  error: string;
  details?: string;
}

export const EditModal: React.FC<EditModalProps> = ({
  title,
  label,
  initialName,
  onClose,
  onUpdate,
}) => {
  const [newName, setNewName] = React.useState(initialName);
  const [error, setError] = useState<{ error: string; details?: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await onUpdate(newName);
      onClose();
    } catch (err) {
      const axiosError = err as AxiosError<ErrorResponse>;
      if (axiosError.response?.data) {
        setError({
          error: axiosError.response.data.error || 'Failed to update',
          details: axiosError.response.data.details
        });
      } else {
        setError({
          error: 'Failed to update',
          details: axiosError.message
        });
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
            <h2 className={MODAL_TITLE}>{title}</h2>
            <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <label htmlFor="rename" className={FIELD_LABEL}>
                {label}
              </label>
              <input
                type="text"
                id="rename"
                name="rename"
                className={FIELD_INPUT}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" onClick={onClose} className={BTN_GHOST}>
                Cancel
              </button>
              <button type="submit" className={BTN_PRIMARY}>
                Save
              </button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}; 