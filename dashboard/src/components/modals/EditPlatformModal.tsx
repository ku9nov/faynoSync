import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { usePlatformQuery, Updater, Platform } from '@/hooks/use-query/usePlatformQuery';
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

interface EditPlatformModalProps {
  platform: Platform;
  platformId: string;
  onClose: () => void;
}

export const EditPlatformModal: React.FC<EditPlatformModalProps> = ({
  platform,
  platformId,
  onClose,
}) => {
  const { updatePlatform } = usePlatformQuery();
  const [name, setName] = useState(platform.PlatformName);
  const [updaters, setUpdaters] = useState<Updater[]>(() => {
    const platformUpdaters = platform.Updaters || [];
    // Ensure manual is always included
    if (!platformUpdaters.find(u => u.type === 'manual')) {
      return [...platformUpdaters, { type: 'manual', default: !platformUpdaters.some(u => u.default) }];
    }
    return platformUpdaters;
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim() && updaters.length > 0) {
      await updatePlatform(platformId, name.trim(), updaters);
      onClose();
    }
  };

  const backdropProps = useBackdropClose(onClose);

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-[500px] max-h-[80vh] overflow-y-auto`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Edit platform</h2>
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
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
