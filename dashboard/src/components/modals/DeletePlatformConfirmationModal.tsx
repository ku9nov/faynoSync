import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeletePlatformConfirmationModalProps {
  platformId: string;
  platformName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeletePlatformConfirmationModal: React.FC<DeletePlatformConfirmationModalProps> = ({
  platformName,
  onClose,
  onConfirm,
}) => {
  return (
    <DeleteEntityModal
      entityName={platformName}
      entityType="platform"
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}; 