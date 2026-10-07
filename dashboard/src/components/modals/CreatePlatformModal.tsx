import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { usePlatformQuery, Updater } from '@/hooks/use-query/usePlatformQuery';
import { UpdatersSelector } from '@/components/common/UpdatersSelector';
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

interface CreatePlatformModalProps {
  onClose: () => void;
}

export const CreatePlatformModal: React.FC<CreatePlatformModalProps> = ({ onClose }) => {
  const { createPlatform } = usePlatformQuery();
  const [name, setName] = useState('');
  const [updaters, setUpdaters] = useState<Updater[]>([
    { type: 'manual', default: true }
  ]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim() && updaters.length > 0) {
      await createPlatform(name.trim(), updaters);
      onClose();
    }
  };

  const backdropProps = useBackdropClose(onClose);

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-[500px] max-h-[80vh] overflow-y-auto`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Create platform</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="mb-6">
            <label htmlFor="name" className={FIELD_LABEL}>
              Platform name
            </label>
            <input
              type="text"
              id="name"
              name="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={FIELD_INPUT}
              required
            />
          </div>
          <div className="mb-6">
            <UpdatersSelector updaters={updaters} onChange={setUpdaters} />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={BTN_GHOST}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim() || updaters.length === 0}
              className={BTN_PRIMARY}
            >
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
