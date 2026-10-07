import React from 'react';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { EditModal } from '@/components/common/EditEntityModal';

interface EditChannelModalProps {
  channelName: string;
  channelId: string;
  onClose: () => void;
}

export const EditChannelModal: React.FC<EditChannelModalProps> = ({
  channelName,
  channelId,
  onClose,
}) => {
  const { updateChannel } = useChannelQuery();

  const handleUpdate = async (newName: string) => {
    await updateChannel(channelId, newName);
  };

  return (
    <EditModal
      title="Edit Channel"
      label="Rename Channel"
      initialName={channelName}
      onClose={onClose}
      onUpdate={handleUpdate}
    />
  );
}; 