import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ReportGroup } from '@/hooks/use-query/useReportsQuery';
import {
  BTN_DANGER,
  BTN_GHOST,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
} from '@/components/common/ui';

interface DeleteReportConfirmationModalProps {
  group: ReportGroup;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

const formatLabel = (value: string) =>
  value
    .split('_')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

export const DeleteReportConfirmationModal: React.FC<DeleteReportConfirmationModalProps> = ({
  group,
  onClose,
  onConfirm,
}) => {
  const [isDeleting, setIsDeleting] = useState(false);
  const backdropProps = useBackdropClose(onClose);

  const handleConfirm = async () => {
    setIsDeleting(true);
    try {
      await onConfirm();
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-96`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Delete report group</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <p className="mb-3 text-sm text-white/70">
          {group.application.name} v{group.application.version} · {formatLabel(group.event.type)} / {formatLabel(group.event.reason)}
        </p>
        <p className="mb-6 flex items-start gap-3 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-3 text-sm text-red-200">
          <i className="fas fa-exclamation-triangle mt-0.5"></i>
          <span>This removes the group, its detail blobs and the stored S3 objects. It cannot be undone.</span>
        </p>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className={BTN_GHOST}>
            Cancel
          </button>
          <button type="button" onClick={handleConfirm} disabled={isDeleting} className={BTN_DANGER}>
            {isDeleting ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  );
};
