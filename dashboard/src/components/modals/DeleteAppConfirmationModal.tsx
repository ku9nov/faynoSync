import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeleteAppConfirmationModalProps {
  appName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteAppConfirmationModal: React.FC<DeleteAppConfirmationModalProps> = ({
  appName,
  onClose,
  onConfirm,
}) => {
  return (
    <DeleteEntityModal
      entityName={appName}
      entityType="app"
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}; 