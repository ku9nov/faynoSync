import React, { useState, useEffect } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ModalFeedback } from '@/components/common/ModalFeedback';
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
} from '@/components/common/ui';

interface EditUserModalProps {
  userId: string;
  username: string;
  isOpen: boolean;
  onClose: () => void;
  onSave: (userId: string, newUsername: string, newPassword: string) => Promise<void>;
}

export const EditUserModal: React.FC<EditUserModalProps> = ({
  userId,
  username,
  isOpen,
  onClose,
  onSave,
}) => {
  const [newUsername, setNewUsername] = useState(username);
  const [newPassword, setNewPassword] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState<string | null>(null);

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen) {
      setNewUsername(username);
      setNewPassword('');
      setError(null);
      setCopySuccess(null);
    }
  }, [isOpen, username]);

  const handleSave = async () => {
    if (!newUsername.trim()) {
      setError('Username cannot be empty');
      return;
    }

    setIsSaving(true);
    setError(null);
    
    try {
      await onSave(userId, newUsername, newPassword);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to update user');
    } finally {
      setIsSaving(false);
    }
  };

  const generatePassword = () => {
    const length = 32;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }
    
    setNewPassword(password);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopySuccess('Password copied to clipboard!');
        setTimeout(() => setCopySuccess(null), 2000);
      },
      (err) => {
        console.error('Could not copy text: ', err);
      }
    );
  };

  const backdropProps = useBackdropClose(onClose);

  if (!isOpen) return null;

  return (
    <>
      <ModalFeedback error={error ? { error } : null} setError={() => setError(null)} />
      <div className={`${MODAL_OVERLAY} z-[10000] min-h-screen overflow-y-auto p-4`} {...backdropProps}>
        <div className={`${MODAL_SURFACE} w-full max-w-md max-h-[90vh]`}>
          <div className={MODAL_HEADER}>
            <h2 className={MODAL_TITLE}>Edit user</h2>
            <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="mb-4">
            <label className={FIELD_LABEL}>Username</label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              className={FIELD_INPUT}
              placeholder="Enter username"
            />
          </div>
          <div className="mb-6">
            <label className={FIELD_LABEL}>New password</label>
            <div className="flex gap-2">
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className={FIELD_INPUT}
                placeholder="Enter new password"
              />
              <button type="button" onClick={generatePassword} className={`${BTN_GHOST} shrink-0 whitespace-nowrap`}>
                Generate
              </button>
              {newPassword && (
                <button
                  type="button"
                  onClick={() => copyToClipboard(newPassword)}
                  className={`${BTN_GHOST} shrink-0`}
                  aria-label="Copy password"
                >
                  <i className="fas fa-copy"></i>
                </button>
              )}
            </div>
            <p className="mt-2 text-xs text-white/55">Leave empty to keep the current password.</p>
            {copySuccess && <p className="mt-1 text-xs text-green-300">{copySuccess}</p>}
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={BTN_GHOST}>
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={isSaving || !newUsername.trim()}
              className={`${BTN_PRIMARY} inline-flex items-center gap-2`}
            >
              {isSaving ? (
                <>
                  <i className="fas fa-spinner fa-spin"></i>
                  Saving...
                </>
              ) : (
                'Save'
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
