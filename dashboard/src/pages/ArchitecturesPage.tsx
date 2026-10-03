import React from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { CreateArchitectureModal } from '@/components/modals/CreateArchitectureModal';
import { EditArchitectureModal } from '@/components/modals/EditArchitectureModal';
import { ArchitectureCard } from '@/components/cards/ArchitectureCard';
import { DeleteArchitectureConfirmationModal } from '@/components/modals/DeleteArchitectureConfirmationModal';
import { useArchitectureQuery, Architecture } from '@/hooks/use-query/useArchitectureQuery.ts';
import { useSearch } from '@/hooks/useSearch.ts';
import '@/styles/cards.css';

export const ArchitecturesPage = () => {
  const [createArchitectureOpen, setCreateArchitectureOpen] =
    React.useState(false);

  const [selectedArchitecture, setSelectedArchitecture] = React.useState<
    { id: string; name: string } | null
  >(null);

  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = React.useState(false);
  const [architectureToDelete, setArchitectureToDelete] = React.useState<{ id: string; name: string } | null>(null);
  const [searchTerm, setSearchTerm] = React.useState('');
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(false);

  const openCreateArchitecture = () => setCreateArchitectureOpen(true);
  const closeCreateArchitecture = () => setCreateArchitectureOpen(false);

  const selectArchitecture = (architecture: Architecture) =>
    setSelectedArchitecture({ id: architecture.ID, name: architecture.ArchID });

  const { architectures, deleteArchitecture, isLoading } = useArchitectureQuery();

  const filteredArchitectures = useSearch(architectures, searchTerm) as Architecture[];

  const handleDelete = async (archId: string, archName: string) => {
    setArchitectureToDelete({ id: archId, name: archName });
    setDeleteConfirmationOpen(true);
  };

  const handleConfirmDelete = async () => {
    if (architectureToDelete) {
      try {
        await deleteArchitecture(architectureToDelete.id);
        setDeleteConfirmationOpen(false);
        setArchitectureToDelete(null);
      } catch (error) {
        console.error('Error deleting architecture:', error);
        throw error;
      }
    }
  };

  return (
    <div className='min-h-screen bg-theme-gradient font-sans'>
      <div className='flex'>
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
        <main className='flex-1 min-w-0 p-8'>
          <Header
            title='Architectures'
            onCreateClick={openCreateArchitecture}
            createButtonText='Create Architecture'
            onSearchChange={setSearchTerm}
            onMenuClick={() => setIsSidebarOpen(true)}
          />
          {isLoading ? (
            <div className="flex justify-center items-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
            </div>
          ) : filteredArchitectures.length === 0 ? (
            <div className="text-center text-theme-primary text-xl mt-8">
              {searchTerm ? 'No architectures found matching your search.' : 'No architectures have been created yet.'}
            </div>
          ) : (
            <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'>
              {filteredArchitectures.map((architecture: Architecture) => (
                <ArchitectureCard
                  key={architecture.ID}
                  archName={architecture.ArchID}
                  onClick={() => selectArchitecture(architecture)}
                  onDelete={() => handleDelete(architecture.ID, architecture.ArchID)}
                />
              ))}
            </div>
          )}
        </main>
      </div>

      {createArchitectureOpen && (
        <CreateArchitectureModal onClose={closeCreateArchitecture} />
      )}

      {selectedArchitecture && (
        <EditArchitectureModal
          archName={selectedArchitecture.name}
          archId={selectedArchitecture.id}
          onClose={() => setSelectedArchitecture(null)}
        />
      )}

      {deleteConfirmationOpen && architectureToDelete && (
        <DeleteArchitectureConfirmationModal
          architectureId={architectureToDelete.id}
          architectureName={architectureToDelete.name}
          onClose={() => {
            setDeleteConfirmationOpen(false);
            setArchitectureToDelete(null);
          }}
          onConfirm={handleConfirmDelete}
        />
      )}
    </div>
  );
};
