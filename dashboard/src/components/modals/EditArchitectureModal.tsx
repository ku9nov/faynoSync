import React from 'react';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { EditModal } from '@/components/common/EditEntityModal';

interface EditArchitectureModalProps {
  archName: string;
  archId: string;
  onClose: () => void;
}

export const EditArchitectureModal: React.FC<EditArchitectureModalProps> = ({
  archName,
  archId,
  onClose,
}) => {
  const { updateArchitecture } = useArchitectureQuery();

  const handleUpdate = async (newName: string) => {
    await updateArchitecture(archId, newName);
  };

  return (
    <EditModal
      title="Edit Architecture"
      label="Rename Architecture"
      initialName={archName}
      onClose={onClose}
      onUpdate={handleUpdate}
    />
  );
};
