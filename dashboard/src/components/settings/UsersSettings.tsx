import React, { useState, useEffect } from 'react';
import { useUsersListQuery } from '@/hooks/use-query/useUsersListQuery';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { AllowedItemsModal } from '@/components/settings/AllowedItemsModal';
import { EditUserModal } from '@/components/settings/EditUserModal';
import axiosInstance from '@/config/axios';
import { useQueryClient } from '@tanstack/react-query';
import { DeleteUserConfirmationModal } from '@/components/settings/DeleteUserConfirmationModal';
import { CreateUserModal } from '@/components/settings/CreateUserModal';

// Add styles for checkboxes
const checkboxStyles = `
  @media (max-width: 768px) {
    .users-settings-checkbox {
      width: 0.75rem !important;
      height: 0.75rem !important;
    }
    
    .table-cell {
      padding: 0.25rem !important;
    }
  }
`;

export const UsersSettings: React.FC = () => {
  const { data: usersData, isLoading, error } = useUsersListQuery();
  const { apps } = useAppsQuery();
  const { channels } = useChannelQuery();
  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();
  const queryClient = useQueryClient();

  // State for modal
  const [modalOpen, setModalOpen] = useState(false);
  const [modalTitle, setModalTitle] = useState('');
  const [modalItems, setModalItems] = useState<{ id: string; name: string }[]>([]);
  const [modalSelectedIds, setModalSelectedIds] = useState<string[]>([]);
  const [modalType, setModalType] = useState<'app' | 'channel' | 'platform' | 'arch'>('app');
  const [currentUserId, setCurrentUserId] = useState<string>('');
  
  // State for tracking modified permissions
  const [modifiedPermissions, setModifiedPermissions] = useState<Record<string, any>>({});
  const [isSaving, setIsSaving] = useState<Record<string, boolean>>({});
  
  // State for delete confirmation modal
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<{ id: string; username: string } | null>(null);
  
  // State for edit user modal
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [userToEdit, setUserToEdit] = useState<{ id: string; username: string } | null>(null);
  
  // State for create user modal
  const [createModalOpen, setCreateModalOpen] = useState(false);

  // Initialize modified permissions when users data is loaded
  useEffect(() => {
    if (usersData?.users) {
      const initialPermissions: Record<string, any> = {};
      usersData.users.forEach(user => {
        initialPermissions[user.id] = {
          permissions: { ...user.permissions }
        };
      });
      setModifiedPermissions(initialPermissions);
    }
  }, [usersData]);


  // Helper function to get all items for a specific type
  const getAllItemsForType = (type: 'app' | 'channel' | 'platform' | 'arch') => {    
    if (type === 'app' && Array.isArray(apps)) {
      return apps.map(app => ({ id: app.ID, name: app.AppName }));
    } else if (type === 'channel' && Array.isArray(channels)) {
      return channels.map(channel => ({ id: channel.ID, name: channel.ChannelName }));
    } else if (type === 'platform' && Array.isArray(platforms)) {
      return platforms.map(platform => ({ id: platform.ID, name: platform.PlatformName }));
    } else if (type === 'arch' && Array.isArray(architectures)) {
      return architectures.map(arch => ({ id: arch.ID, name: arch.ArchID }));
    }
    
    return [];
  };

  // Helper function to get valid allowed items count
  const getAllowedCount = (allowed: string[] | undefined): number => {
    if (!allowed || allowed.length === 0) return 0;
    
    // Filter out empty strings
    const validItems = allowed.filter(id => id && id.trim() !== '');
    return validItems.length;
  };

  // Function to open the modal
  const openAllowedModal = (
    userId: string,
    type: 'app' | 'channel' | 'platform' | 'arch',
    allowedIds: string[]
  ) => {
    setCurrentUserId(userId);
    setModalType(type);
    
    // Filter out empty strings
    const validIds = allowedIds.filter(id => id && id.trim() !== '');
    setModalSelectedIds(validIds);
    
    // Set title based on type
    const typeTitle = type.charAt(0).toUpperCase() + type.slice(1);
    setModalTitle(`Allowed ${typeTitle}s`);
    
    // Set items based on type
    setModalItems(getAllItemsForType(type));
    
    // Open modal
    setModalOpen(true);
  };

  // Function to handle saving allowed items
  const handleSaveAllowedItems = (selectedIds: string[]) => {
    if (!currentUserId) return;
    
    // Update the modified permissions with the new allowed items
    setModifiedPermissions(prev => {
      const updated = { ...prev };
      const userPermissions = { ...updated[currentUserId].permissions };
      
      if (modalType === 'app') {
        userPermissions.Apps = { 
          ...userPermissions.Apps, 
          Allowed: selectedIds 
        };
      } else if (modalType === 'channel') {
        userPermissions.Channels = { 
          ...userPermissions.Channels, 
          Allowed: selectedIds 
        };
      } else if (modalType === 'platform') {
        userPermissions.Platforms = { 
          ...userPermissions.Platforms, 
          Allowed: selectedIds 
        };
      } else if (modalType === 'arch') {
        userPermissions.Archs = { 
          ...userPermissions.Archs, 
          Allowed: selectedIds 
        };
      }
      
      updated[currentUserId] = {
        ...updated[currentUserId],
        permissions: userPermissions
      };
      
      return updated;
    });
    
    // Close the modal
    setModalOpen(false);
  };

  // Function to handle permission checkbox change
  const handlePermissionChange = (
    userId: string, 
    category: 'Apps' | 'Channels' | 'Platforms' | 'Archs', 
    permission: 'Create' | 'Delete' | 'Edit' | 'Download' | 'Upload', 
    checked: boolean
  ) => {
    setModifiedPermissions(prev => {
      const updated = { ...prev };
      const userPermissions = { ...updated[userId].permissions };
      
      if (!userPermissions[category]) {
        userPermissions[category] = {
          Create: false,
          Delete: false,
          Edit: false,
          Allowed: []
        };
        
        // Add optional permissions for Apps
        if (category === 'Apps') {
          userPermissions[category].Download = false;
          userPermissions[category].Upload = false;
        }
      }
      
      userPermissions[category] = {
        ...userPermissions[category],
        [permission]: checked
      };
      
      updated[userId] = {
        ...updated[userId],
        permissions: userPermissions
      };
      
      return updated;
    });
  };

  // Function to handle saving user permissions
  const handleSaveUserPermissions = async (userId: string) => {
    if (!modifiedPermissions[userId]) return;
    
    setIsSaving(prev => ({ ...prev, [userId]: true }));
    
    try {
      const user = usersData?.users.find(u => u.id === userId);
      if (!user) return;
      
      // Prepare the data for the API request
      const permissions = modifiedPermissions[userId].permissions;
      
      const requestData = {
        id: userId,
        username: user.username,
        permissions: {
          apps: {
            create: permissions.Apps?.Create || false,
            delete: permissions.Apps?.Delete || false,
            edit: permissions.Apps?.Edit || false,
            download: permissions.Apps?.Download || false,
            upload: permissions.Apps?.Upload || false,
            allowed: permissions.Apps?.Allowed || []
          },
          channels: {
            create: permissions.Channels?.Create || false,
            delete: permissions.Channels?.Delete || false,
            edit: permissions.Channels?.Edit || false,
            allowed: permissions.Channels?.Allowed || []
          },
          platforms: {
            create: permissions.Platforms?.Create || false,
            delete: permissions.Platforms?.Delete || false,
            edit: permissions.Platforms?.Edit || false,
            allowed: permissions.Platforms?.Allowed || []
          },
          archs: {
            create: permissions.Archs?.Create || false,
            delete: permissions.Archs?.Delete || false,
            edit: permissions.Archs?.Edit || false,
            allowed: permissions.Archs?.Allowed || []
          }
        }
      };
      
      // Send the request to the API
      await axiosInstance.post('/user/update', requestData);
      
      // Invalidate the users list query to refresh the data
      queryClient.invalidateQueries({ queryKey: ['users-list'] });
      
    } catch (error) {
      console.error('Error saving user permissions:', error);
    } finally {
      setIsSaving(prev => ({ ...prev, [userId]: false }));
    }
  };

  // Function to open delete confirmation modal
  const openDeleteModal = (userId: string, username: string) => {
    setUserToDelete({ id: userId, username });
    setDeleteModalOpen(true);
  };

  // Function to handle deleting user
  const handleDeleteUser = async () => {
    if (!userToDelete) return;
    
    try {
      // Send the delete request to the API
      await axiosInstance.delete('/user/delete', {
        data: { id: userToDelete.id }
      });
      
      // Invalidate the users list query to refresh the data
      queryClient.invalidateQueries({ queryKey: ['users-list'] });
      
      // Close the modal
      setDeleteModalOpen(false);
      setUserToDelete(null);
    } catch (error) {
      console.error('Error deleting user:', error);
      throw error;
    }
  };

  // Function to open edit user modal
  const openEditModal = (userId: string, username: string) => {
    setUserToEdit({ id: userId, username });
    setEditModalOpen(true);
  };

  // Function to handle saving user details
  const handleSaveUserDetails = async (userId: string, newUsername: string, newPassword: string) => {
    try {
      // Find the user to get their current permissions
      const user = usersData?.users.find(u => u.id === userId);
      if (!user) return;
      
      // Prepare the data for the API request
      const requestData: any = {
        id: userId,
        username: newUsername,
        permissions: {
          apps: {
            create: user.permissions.Apps?.Create || false,
            delete: user.permissions.Apps?.Delete || false,
            edit: user.permissions.Apps?.Edit || false,
            download: user.permissions.Apps?.Download || false,
            upload: user.permissions.Apps?.Upload || false,
            allowed: user.permissions.Apps?.Allowed || []
          },
          channels: {
            create: user.permissions.Channels?.Create || false,
            delete: user.permissions.Channels?.Delete || false,
            edit: user.permissions.Channels?.Edit || false,
            allowed: user.permissions.Channels?.Allowed || []
          },
          platforms: {
            create: user.permissions.Platforms?.Create || false,
            delete: user.permissions.Platforms?.Delete || false,
            edit: user.permissions.Platforms?.Edit || false,
            allowed: user.permissions.Platforms?.Allowed || []
          },
          archs: {
            create: user.permissions.Archs?.Create || false,
            delete: user.permissions.Archs?.Delete || false,
            edit: user.permissions.Archs?.Edit || false,
            allowed: user.permissions.Archs?.Allowed || []
          }
        }
      };
      
      // Add password only if it's provided
      if (newPassword) {
        requestData.password = newPassword;
      }
      
      // Send the request to the API
      await axiosInstance.post('/user/update', requestData);
      
      // Invalidate the users list query to refresh the data
      queryClient.invalidateQueries({ queryKey: ['users-list'] });
      
    } catch (error) {
      console.error('Error updating user details:', error);
      throw error;
    }
  };

  // Function to handle creating a new user
  const handleCreateUser = async (username: string, password: string, permissions: any) => {
    try {
      // Prepare the data for the API request
      const requestData = {
        username,
        password,
        permissions: {
          apps: {
            create: permissions.apps.create,
            delete: permissions.apps.delete,
            edit: permissions.apps.edit,
            download: permissions.apps.download,
            upload: permissions.apps.upload,
            allowed: permissions.apps.allowed
          },
          channels: {
            create: permissions.channels.create,
            delete: permissions.channels.delete,
            edit: permissions.channels.edit,
            allowed: permissions.channels.allowed
          },
          platforms: {
            create: permissions.platforms.create,
            delete: permissions.platforms.delete,
            edit: permissions.platforms.edit,
            allowed: permissions.platforms.allowed
          },
          archs: {
            create: permissions.archs.create,
            delete: permissions.archs.delete,
            edit: permissions.archs.edit,
            allowed: permissions.archs.allowed
          }
        }
      };
      
      // Send the request to the API
      await axiosInstance.post('/user/create', requestData);
      
      // Invalidate the users list query to refresh the data
      queryClient.invalidateQueries({ queryKey: ['users-list'] });
      
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  };

  // Update the handleEditUser function
  const handleEditUser = (userId: string) => {
    const user = usersData?.users.find(u => u.id === userId);
    if (user) {
      openEditModal(userId, user.username);
    }
  };

  if (isLoading) {
    return <div className="text-theme-primary">Loading...</div>;
  }

  if (error) {
    return <div className="text-theme-danger">Error loading users data</div>;
  }

  return (
    <div className="relative">
      <style>{checkboxStyles}</style>
      <div className="users-table-container text-sm">
        {/* Add Create User button at the top - moved outside the conditional rendering */}
        <div className="mb-4 flex justify-end">
          <button
            onClick={() => setCreateModalOpen(true)}
            className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors duration-200"
          >
            <i className="fas fa-user-plus mr-2"></i>
            Create User
          </button>
        </div>
        
        {!usersData?.users || usersData.users.length === 0 ? (
          <div className="text-theme-primary p-4 text-center">No users found</div>
        ) : (
          <>
            {/* Single scrollable container */}
            <div className="overflow-x-auto">
              <div className="min-w-full inline-block align-middle">
                <div className="overflow-hidden">
                  <table className="users-table table-fixed">
                    <colgroup>
                      <col className="username-cell" /><col className="checkbox-cell" span={6} /><col className="checkbox-cell" span={4} /><col className="checkbox-cell" span={4} /><col className="checkbox-cell" span={4} /><col className="action-cell" />
                    </colgroup>
                    <thead>
                      <tr>
                        <th className="px-2 py-1 text-left">Username</th>
                        <th className="px-2 py-1 text-center" colSpan={6}>
                          Apps
                        </th>
                        <th className="px-2 py-1 text-center" colSpan={4}>
                          Channels
                        </th>
                        <th className="px-2 py-1 text-center" colSpan={4}>
                          Platforms
                        </th>
                        <th className="px-2 py-1 text-center" colSpan={4}>
                          Architectures
                        </th>
                        <th className="px-2 py-1 text-center">
                          Actions
                        </th>
                      </tr>
                      <tr>
                        <th className="px-2 py-1"></th>
                        {/* Apps subheaders */}
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Create</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Delete</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Edit</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Download</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Upload</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Allowed</div>
                        </th>
                        {/* Channels subheaders */}
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Create</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Delete</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Edit</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Allowed</div>
                        </th>
                        {/* Platforms subheaders */}
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Create</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Delete</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Edit</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Allowed</div>
                        </th>
                        {/* Archs subheaders */}
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Create</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Delete</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Edit</div>
                        </th>
                        <th className="min-w-[40px] h-32 text-center">
                          <div className="transform -rotate-90 whitespace-nowrap h-full flex items-center justify-center">Allowed</div>
                        </th>
                        <th className="px-2 py-1 text-center"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {usersData.users.map((user) => (
                        <tr key={user.id}>
                          <td className="px-2 py-1 table-cell">
                            <div 
                              className="truncate max-w-[300px]" 
                              title={user.username}
                            >
                              {JSON.stringify(modifiedPermissions[user.id]?.permissions) !== JSON.stringify(user.permissions) && (
                                <span className="ml-2 text-yellow-500" title="Unsaved changes" style={{ marginRight: '5px' }}>
                                  <i className="fas fa-exclamation-circle"></i>
                                </span>
                              )}
                              {user.username}
                            </div>
                          </td>
                          {/* Apps permissions */}
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Apps?.Create || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Apps', 'Create', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Apps?.Delete || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Apps', 'Delete', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Apps?.Edit || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Apps', 'Edit', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Apps?.Download || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Apps', 'Download', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Apps?.Upload || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Apps', 'Upload', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <button 
                              onClick={() => openAllowedModal(user.id, 'app', modifiedPermissions[user.id]?.permissions?.Apps?.Allowed || [])}
                              className="flex items-center justify-center text-theme-primary hover:text-theme-button-primary"
                            >
                              <i className="fas fa-search"></i>
                              <span>{getAllowedCount(modifiedPermissions[user.id]?.permissions?.Apps?.Allowed)}</span>
                            </button>
                          </td>
                          {/* Channels permissions */}
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Channels?.Create || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Channels', 'Create', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Channels?.Delete || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Channels', 'Delete', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Channels?.Edit || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Channels', 'Edit', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <button 
                              onClick={() => openAllowedModal(user.id, 'channel', modifiedPermissions[user.id]?.permissions?.Channels?.Allowed || [])}
                              className="flex items-center justify-center text-theme-primary hover:text-theme-button-primary"
                            >
                              <i className="fas fa-search"></i>
                              <span>{getAllowedCount(modifiedPermissions[user.id]?.permissions?.Channels?.Allowed)}</span>
                            </button>
                          </td>
                          {/* Platforms permissions */}
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Platforms?.Create || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Platforms', 'Create', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Platforms?.Delete || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Platforms', 'Delete', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Platforms?.Edit || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Platforms', 'Edit', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <button 
                              onClick={() => openAllowedModal(
                                user.id, 
                                'platform', 
                                modifiedPermissions[user.id]?.permissions?.Platforms?.Allowed || []
                              )}
                              className="flex items-center justify-center space-x-1 text-theme-primary hover:text-theme-button-primary"
                            >
                              <i className="fas fa-search"></i>
                              <span>{getAllowedCount(modifiedPermissions[user.id]?.permissions?.Platforms?.Allowed)}</span>
                            </button>
                          </td>
                          {/* Archs permissions */}
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Archs?.Create || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Archs', 'Create', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Archs?.Delete || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Archs', 'Delete', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <input 
                              type="checkbox" 
                              checked={modifiedPermissions[user.id]?.permissions?.Archs?.Edit || false}
                              onChange={(e) => handlePermissionChange(user.id, 'Archs', 'Edit', e.target.checked)}
                              className="users-settings-checkbox w-4 h-4"
                            />
                          </td>
                          <td className="px-2 py-1 text-center table-cell">
                            <button 
                              onClick={() => openAllowedModal(user.id, 'arch', modifiedPermissions[user.id]?.permissions?.Archs?.Allowed || [])}
                              className="flex items-center justify-center text-theme-primary hover:text-theme-button-primary"
                            >
                              <i className="fas fa-search"></i>
                              <span>{getAllowedCount(modifiedPermissions[user.id]?.permissions?.Archs?.Allowed)}</span>
                            </button>
                          </td>
                          {/* Action buttons */}
                          <td className="px-2 py-1 text-center table-cell">
                            <div className="flex justify-center space-x-1">
                              <button 
                                onClick={() => handleSaveUserPermissions(user.id)}
                                className={`users-table-action-btn ${isSaving[user.id] ? 'opacity-50 cursor-not-allowed' : ''} ${JSON.stringify(modifiedPermissions[user.id]?.permissions) !== JSON.stringify(user.permissions) ? 'text-yellow-500' : ''}`}
                                title="Save user permissions"
                                disabled={isSaving[user.id]}
                              >
                                {isSaving[user.id] ? (
                                  <i className="fas fa-spinner fa-spin"></i>
                                ) : (
                                  <i className="fas fa-save"></i>
                                )}
                              </button>
                              <button 
                                onClick={() => handleEditUser(user.id)}
                                className="users-table-action-btn"
                                title="Edit user"
                              >
                                <i className="fas fa-edit"></i>
                              </button>
                              <button 
                                onClick={() => openDeleteModal(user.id, user.username)}
                                className="users-table-action-btn"
                                title="Delete user"
                              >
                                <i className="fas fa-trash-alt"></i>
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Modal for editing allowed items */}
      <AllowedItemsModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={modalTitle}
        items={modalItems}
        selectedIds={modalSelectedIds}
        onSave={handleSaveAllowedItems}
      />
      
      {/* Delete confirmation modal */}
      {userToDelete && (
        <DeleteUserConfirmationModal
          userId={userToDelete.id}
          username={userToDelete.username}
          isOpen={deleteModalOpen}
          onClose={() => {
            setDeleteModalOpen(false);
            setUserToDelete(null);
          }}
          onConfirm={handleDeleteUser}
        />
      )}
      
      {/* Edit user modal */}
      {userToEdit && (
        <EditUserModal
          userId={userToEdit.id}
          username={userToEdit.username}
          isOpen={editModalOpen}
          onClose={() => {
            setEditModalOpen(false);
            setUserToEdit(null);
          }}
          onSave={handleSaveUserDetails}
        />
      )}
      
      {/* Create user modal */}
      <CreateUserModal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        onSave={handleCreateUser}
      />
    </div>
  );
}; 