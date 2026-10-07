import React from 'react';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { CreateEntityModal } from '@/components/common/CreateEntityModal';

interface CreateChannelModalProps {
  onClose: () => void;
}

export const CreateChannelModal: React.FC<CreateChannelModalProps> = ({ onClose }) => {
  const { createChannel } = useChannelQuery();

  return (
    <CreateEntityModal
      onClose={onClose}
      title="Create Channel"
      entityName="Channel Name"
      onSubmit={createChannel}
    />
  );
}; 