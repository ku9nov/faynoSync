import React from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { CreateChannelModal } from '@/components/modals/CreateChannelModal';
import { EditChannelModal } from '@/components/modals/EditChannelModal';
import { ChannelCard } from '@/components/cards/ChannelCard';
import { DeleteChannelConfirmationModal } from '@/components/modals/DeleteChannelConfirmationModal';
import { useChannelQuery, Channel } from '@/hooks/use-query/useChannelQuery';
import { useSearch } from '@/hooks/useSearch.ts';
import '@/styles/cards.css';

export const ChannelsPage = () => {
  const [isCreateModalOpen, setIsCreateModalOpen] = React.useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = React.useState(false);
  const [selectedChannel, setSelectedChannel] = React.useState<Channel | null>(null);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = React.useState(false);
  const [channelToDelete, setChannelToDelete] = React.useState<{ id: string; name: string } | null>(null);
  const [searchTerm, setSearchTerm] = React.useState('');
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(false);

  const openCreateModal = () => setIsCreateModalOpen(true);
  const closeCreateModal = () => setIsCreateModalOpen(false);
  const openEditModal = (channel: Channel) => {
    setSelectedChannel(channel);
    setIsEditModalOpen(true);
  };
  const closeEditModal = () => {
    setSelectedChannel(null);
    setIsEditModalOpen(false);
  };

  const { channels, deleteChannel, isLoading } = useChannelQuery();

  const filteredChannels = useSearch(channels, searchTerm) as Channel[];

  const handleDelete = async (channelId: string, channelName: string) => {
    setChannelToDelete({ id: channelId, name: channelName });
    setDeleteConfirmationOpen(true);
  };

  const handleConfirmDelete = async () => {
    if (channelToDelete) {
      try {
        await deleteChannel(channelToDelete.id);
        setDeleteConfirmationOpen(false);
        setChannelToDelete(null);
      } catch (error) {
        console.error('Error deleting channel:', error);
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
            title="Channels"
            onCreateClick={openCreateModal}
            createButtonText="Create Channel"
            onSearchChange={setSearchTerm}
            onMenuClick={() => setIsSidebarOpen(true)}
          />
          {isLoading ? (
            <div className="flex justify-center items-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
            </div>
          ) : filteredChannels.length === 0 ? (
            <div className="text-center text-theme-primary text-xl mt-8">
              {searchTerm ? 'No channels found matching your search.' : 'No channels have been created yet.'}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredChannels.map((channel) => (
                <ChannelCard
                  key={channel.ID}
                  name={channel.ChannelName}
                  // description={`Last updated: ${new Date(channel.Updated_at).toLocaleDateString()}`}
                  onClick={() => openEditModal(channel)}
                  onDelete={() => handleDelete(channel.ID, channel.ChannelName)}
                />
              ))}
            </div>
          )}
        </main>
      </div>

      {isCreateModalOpen && (
        <CreateChannelModal onClose={closeCreateModal} />
      )}

      {isEditModalOpen && selectedChannel && (
        <EditChannelModal
          channelName={selectedChannel.ChannelName}
          channelId={selectedChannel.ID}
          onClose={closeEditModal}
        />
      )}

      {deleteConfirmationOpen && channelToDelete && (
        <DeleteChannelConfirmationModal
          channelId={channelToDelete.id}
          channelName={channelToDelete.name}
          onClose={() => {
            setDeleteConfirmationOpen(false);
            setChannelToDelete(null);
          }}
          onConfirm={handleConfirmDelete}
        />
      )}
    </div>
  );
}; 