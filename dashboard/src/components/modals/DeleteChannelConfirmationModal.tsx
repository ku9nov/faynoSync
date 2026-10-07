import React from 'react';
import { DeleteEntityModal } from '@/components/common/DeleteEntityModal';

interface DeleteChannelConfirmationModalProps {
  channelId: string;
  channelName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export const DeleteChannelConfirmationModal: React.FC<DeleteChannelConfirmationModalProps> = ({
  channelName,
  onClose,
  onConfirm,
}) => {
  return (
    <DeleteEntityModal
      entityName={channelName}
      entityType="channel"
      onClose={onClose}
      onConfirm={onConfirm}
    />
  );
}; 