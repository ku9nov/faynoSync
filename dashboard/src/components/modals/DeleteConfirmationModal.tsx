import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeleteConfirmationModalProps {
  version: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteConfirmationModal: React.FC<DeleteConfirmationModalProps> = ({
  version,
  onClose,
  onConfirm,
}) => {
  return (
    <DeleteEntityModal
      entityName={version}
      entityType="version"
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}; 