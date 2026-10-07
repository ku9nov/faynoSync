import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeleteArchitectureConfirmationModalProps {
  architectureId: string;
  architectureName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteArchitectureConfirmationModal: React.FC<DeleteArchitectureConfirmationModalProps> = ({
  architectureName,
  onClose,
  onConfirm,
}) => {
  return (
    <DeleteEntityModal
      entityName={architectureName}
      entityType="architecture"
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}; 