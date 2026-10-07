import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeleteArtifactConfirmationModalProps {
  platform: string;
  arch: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteArtifactConfirmationModal: React.FC<DeleteArtifactConfirmationModalProps> = ({
  platform,
  arch,
  onClose,
  onConfirm,
}) => {
  const confirmationValue = `${platform}/${arch}`;
  return (
    <DeleteEntityModal
      entityName={confirmationValue}
      entityType="artifact"
      onClose={onClose}
      onConfirm={onConfirm}
      confirmationValue={confirmationValue}
    />
  );
}; 