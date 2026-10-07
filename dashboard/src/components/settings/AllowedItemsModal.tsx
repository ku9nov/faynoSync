import React, { useState, useEffect } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import {
  BTN_GHOST,
  BTN_PRIMARY,
  MODAL_CLOSE,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
} from '@/components/common/ui';

interface AllowedItemsModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  items: { id: string; name: string }[];
  selectedIds: string[];
  onSave: (selectedIds: string[]) => void;
}

export const AllowedItemsModal: React.FC<AllowedItemsModalProps> = ({
  isOpen,
  onClose,
  title,
  items,
  selectedIds,
  onSave,
}) => {
  const [selected, setSelected] = useState<string[]>([]);

  useEffect(() => {
    if (isOpen) {
      setSelected([...selectedIds]);
    }
  }, [isOpen, selectedIds]);

  const handleToggleItem = (id: string) => {
    if (selected.includes(id)) {
      setSelected(selected.filter(itemId => itemId !== id));
    } else {
      setSelected([...selected, id]);
    }
  };

  const handleSave = () => {
    onSave(selected);
    onClose();
  };

  const handleSelectAll = () => {
    setSelected(items.map((item) => item.id));
  };

  const backdropProps = useBackdropClose(onClose);

  if (!isOpen) return null;

  return (
    <div
      className={`${MODAL_OVERLAY} z-[10000] min-h-screen overflow-y-auto p-4`}
      {...backdropProps}
    >
      <div
        className={`${MODAL_SURFACE} flex w-full max-w-md max-h-[90vh] flex-col overflow-hidden p-0`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-4 border-b border-white/15 p-4">
          <h2 className={MODAL_TITLE}>{title}</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <i className="fas fa-times text-xl"></i>
          </button>
        </div>

        <div className="flex-grow overflow-y-auto p-4">
          <div className="flex flex-col gap-2">
            {items.map((item) => (
              <FlagCheckbox
                key={item.id}
                label={item.name}
                checked={selected.includes(item.id)}
                onChange={() => handleToggleItem(item.id)}
              />
            ))}
          </div>
        </div>

        <div className="flex justify-end gap-2 border-t border-white/15 p-4">
          <button onClick={handleSelectAll} className={BTN_GHOST}>
            Select all
          </button>
          <button onClick={handleSave} className={BTN_PRIMARY}>
            Update list
          </button>
        </div>
      </div>
    </div>
  );
};
