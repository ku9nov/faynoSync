import React from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { CreatePlatformModal } from '@/components/modals/CreatePlatformModal';
import { EditPlatformModal } from '@/components/modals/EditPlatformModal';
import { PlatformCard } from '@/components/cards/PlatformCard';
import { DeletePlatformConfirmationModal } from '@/components/modals/DeletePlatformConfirmationModal';
import { usePlatformQuery, Platform } from '@/hooks/use-query/usePlatformQuery';
import { useSearch } from '@/hooks/useSearch.ts';
import '@/styles/cards.css';

export const PlatformsPage = () => {
  const [createPlatformOpen, setCreatePlatformOpen] = React.useState(false);
  const [selectedPlatform, setSelectedPlatform] = React.useState<Platform | null>(null);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = React.useState(false);
  const [platformToDelete, setPlatformToDelete] = React.useState<{ id: string; name: string } | null>(null);
  const [searchTerm, setSearchTerm] = React.useState('');
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(false);

  const openCreatePlatform = () => setCreatePlatformOpen(true);
  const closeCreatePlatform = () => setCreatePlatformOpen(false);

  const selectPlatform = (platform: Platform) => setSelectedPlatform(platform);

  const { platforms, deletePlatform, isLoading } = usePlatformQuery();

  const filteredPlatforms = useSearch(platforms, searchTerm) as Platform[];

  const handleDelete = async (platformId: string, platformName: string) => {
    setPlatformToDelete({ id: platformId, name: platformName });
    setDeleteConfirmationOpen(true);
  };

  const handleConfirmDelete = async () => {
    if (platformToDelete) {
      try {
        await deletePlatform(platformToDelete.id);
        setDeleteConfirmationOpen(false);
        setPlatformToDelete(null);
      } catch (error) {
        console.error('Error deleting platform:', error);
        throw error;
      }
    }
  };

  return (
    <div className="min-h-screen bg-theme-gradient font-sans">
      <div className="flex">
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
        <main className="flex-1 min-w-0 p-8">
          <Header
            title="Platforms"
            onCreateClick={openCreatePlatform}
            createButtonText="Create Platform"
            onSearchChange={setSearchTerm}
            onMenuClick={() => setIsSidebarOpen(true)}
          />
          {isLoading ? (
            <div className="flex justify-center items-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
            </div>
          ) : filteredPlatforms.length === 0 ? (
            <div className="text-center text-theme-primary text-xl mt-8">
              {searchTerm ? 'No platforms found matching your search.' : 'No platforms have been created yet.'}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredPlatforms.map((platform) => (
                <PlatformCard
                  key={platform.ID}
                  platform={platform}
                  onClick={() => selectPlatform(platform)}
                  onDelete={() => handleDelete(platform.ID, platform.PlatformName)}
                />
              ))}
            </div>
          )}
        </main>
      </div>

      {createPlatformOpen && (
        <CreatePlatformModal onClose={closeCreatePlatform} />
      )}

      {selectedPlatform && (
        <EditPlatformModal
          platform={selectedPlatform}
          platformId={selectedPlatform.ID}
          onClose={() => setSelectedPlatform(null)}
        />
      )}

      {deleteConfirmationOpen && platformToDelete && (
        <DeletePlatformConfirmationModal
          platformId={platformToDelete.id}
          platformName={platformToDelete.name}
          onClose={() => {
            setDeleteConfirmationOpen(false);
            setPlatformToDelete(null);
          }}
          onConfirm={handleConfirmDelete}
        />
      )}
    </div>
  );
}; 