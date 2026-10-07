import React from 'react';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { CreateEntityModal } from '@/components/common/CreateEntityModal';

interface CreateArchitectureModalProps {
  onClose: () => void;
}

export const CreateArchitectureModal: React.FC<CreateArchitectureModalProps> = ({
  onClose,
}) => {
  const { createArchitecture } = useArchitectureQuery();

  return (
    <CreateEntityModal
      onClose={onClose}
      title="Create Architecture"
      entityName="Architecture Name"
      onSubmit={createArchitecture}
    />
  );
}; 