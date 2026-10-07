import React, { useState, useEffect } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { Dropdown } from '@/components/common/Dropdown';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { ModalFeedback } from '@/components/common/ModalFeedback';
import {
  BTN_GHOST,
  BTN_PRIMARY,
  FIELD_INPUT,
  FIELD_LABEL,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
  SECTION_LABEL,
  STATUS_BADGE,
} from '@/components/common/ui';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';

// Define proper types for permissions
interface Permission {
  create: boolean;
  delete: boolean;
  edit: boolean;
  download?: boolean;
  upload?: boolean;
  allowed: string[];
}

interface Permissions {
  apps: Permission;
  channels: Permission;
  platforms: Permission;
  archs: Permission;
}

interface CreateUserModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (username: string, password: string, permissions: any) => Promise<void>;
}

export const CreateUserModal: React.FC<CreateUserModalProps> = ({
  isOpen,
  onClose,
  onSave,
}) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState<string | null>(null);
  
  // Default permissions with proper typing
  const [permissions, setPermissions] = useState<Permissions>({
    apps: {
      create: false,
      delete: false,
      edit: false,
      download: false,
      upload: false,
      allowed: []
    },
    channels: {
      create: false,
      delete: false,
      edit: false,
      allowed: []
    },
    platforms: {
      create: false,
      delete: false,
      edit: false,
      allowed: []
    },
    archs: {
      create: false,
      delete: false,
      edit: false,
      allowed: []
    }
  });
  
  // State for allowed items dropdowns

  // Get data for dropdowns
  const { apps } = useAppsQuery();
  const { channels } = useChannelQuery();
  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen) {
      setUsername('');
      setPassword('');
      setError(null);
      setCopySuccess(null);
      setPermissions({
        apps: {
          create: false,
          delete: false,
          edit: false,
          download: false,
          upload: false,
          allowed: []
        },
        channels: {
          create: false,
          delete: false,
          edit: false,
          allowed: []
        },
        platforms: {
          create: false,
          delete: false,
          edit: false,
          allowed: []
        },
        archs: {
          create: false,
          delete: false,
          edit: false,
          allowed: []
        }
      });
    }
  }, [isOpen]);

  const handleSave = async () => {
    if (!username.trim()) {
      setError('Username cannot be empty');
      return;
    }
    
    if (!password.trim()) {
      setError('Password cannot be empty');
      return;
    }

    setIsSaving(true);
    setError(null);
    
    try {
      await onSave(username, password, permissions);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create user');
    } finally {
      setIsSaving(false);
    }
  };

  const generatePassword = () => {
    const length = 32;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let generatedPassword = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      generatedPassword += charset[randomIndex];
    }
    
    setPassword(generatedPassword);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopySuccess('Password copied to clipboard!');
        setTimeout(() => setCopySuccess(null), 2000);
      },
      (err) => {
        console.error('Could not copy text: ', err);
      }
    );
  };

  const handlePermissionChange = (category: string, permission: string, checked: boolean) => {
    setPermissions(prev => {
      const updated = { ...prev };
      if (category === 'apps') {
        updated.apps = {
          ...updated.apps,
          [permission]: checked
        };
      } else if (category === 'channels') {
        updated.channels = {
          ...updated.channels,
          [permission]: checked
        };
      } else if (category === 'platforms') {
        updated.platforms = {
          ...updated.platforms,
          [permission]: checked
        };
      } else if (category === 'archs') {
        updated.archs = {
          ...updated.archs,
          [permission]: checked
        };
      }
      return updated;
    });
  };
  
  const handleAllowedItemSelect = (category: string, itemId: string) => {
    setPermissions(prev => {
      const updated = { ...prev };
      if (category === 'apps') {
        if (!updated.apps.allowed.includes(itemId)) {
          updated.apps.allowed = [...updated.apps.allowed, itemId];
        }
      } else if (category === 'channels') {
        if (!updated.channels.allowed.includes(itemId)) {
          updated.channels.allowed = [...updated.channels.allowed, itemId];
        }
      } else if (category === 'platforms') {
        if (!updated.platforms.allowed.includes(itemId)) {
          updated.platforms.allowed = [...updated.platforms.allowed, itemId];
        }
      } else if (category === 'archs') {
        if (!updated.archs.allowed.includes(itemId)) {
          updated.archs.allowed = [...updated.archs.allowed, itemId];
        }
      }
      return updated;
    });
  };
  
  const handleRemoveAllowedItem = (category: string, itemId: string) => {
    setPermissions(prev => {
      const updated = { ...prev };
      if (category === 'apps') {
        updated.apps.allowed = updated.apps.allowed.filter(id => id !== itemId);
      } else if (category === 'channels') {
        updated.channels.allowed = updated.channels.allowed.filter(id => id !== itemId);
      } else if (category === 'platforms') {
        updated.platforms.allowed = updated.platforms.allowed.filter(id => id !== itemId);
      } else if (category === 'archs') {
        updated.archs.allowed = updated.archs.allowed.filter(id => id !== itemId);
      }
      return updated;
    });
  };
  
  const getNameById = (id: string, type: 'app' | 'channel' | 'platform' | 'arch') => {
    let items: any[] = [];
    
    if (type === 'app' && Array.isArray(apps)) {
      items = apps;
      return items.find(item => item.ID === id)?.AppName || id;
    } else if (type === 'channel' && Array.isArray(channels)) {
      items = channels;
      return items.find(item => item.ID === id)?.ChannelName || id;
    } else if (type === 'platform' && Array.isArray(platforms)) {
      items = platforms;
      return items.find(item => item.ID === id)?.PlatformName || id;
    } else if (type === 'arch' && Array.isArray(architectures)) {
      items = architectures;
      return items.find(item => item.ID === id)?.ArchID || id;
    }
    
    return id;
  };

  const backdropProps = useBackdropClose(onClose);

  if (!isOpen) return null;

  return (
    <>
      <ModalFeedback error={error ? { error } : null} setError={() => setError(null)} />
      <div className={`${MODAL_OVERLAY} z-[10000] min-h-screen overflow-y-auto p-4`} {...backdropProps}>
        <div className={`${MODAL_SURFACE} w-full max-w-4xl max-h-[90vh] overflow-y-auto`}>
          <div className={MODAL_HEADER}>
            <h2 className={MODAL_TITLE}>Create user</h2>
            <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          
          <div className='grid grid-cols-2 gap-6'>
            <div>
              <div className='mb-4'>
                <label className={FIELD_LABEL}>Username</label>
                <input
                  type='text'
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className={FIELD_INPUT}
                  placeholder='Enter username'
                />
              </div>
              <div className='mb-4'>
                <label className={FIELD_LABEL}>Password</label>
                <div className='flex gap-2'>
                  <input
                    type='password'
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={FIELD_INPUT}
                    placeholder='Enter password'
                  />
                  <button
                    type='button'
                    onClick={generatePassword}
                    className={`${BTN_GHOST} shrink-0`}
                  >
                    Generate
                  </button>
                  {password && (
                    <button
                      type='button'
                      onClick={() => copyToClipboard(password)}
                      className={`${BTN_GHOST} shrink-0`}
                      aria-label='Copy password'
                    >
                      <i className='fas fa-copy'></i>
                    </button>
                  )}
                </div>
                {copySuccess && (
                  <p className='text-sm text-green-500 mt-1'>{copySuccess}</p>
                )}
              </div>
            </div>
            
            <div>
              <h3 className='text-lg font-bold mb-3 text-theme-primary'>Default Permissions</h3>
              
              <div className='mb-4'>
                <h4 className={`${SECTION_LABEL} mb-2`}>Apps</h4>
                <div className='grid grid-cols-2 gap-2'>
                  <FlagCheckbox
                    label="Create"
                    checked={permissions.apps.create}
                    onChange={(checked) => handlePermissionChange('apps', 'create', checked)}
                  />
                  <FlagCheckbox
                    label="Delete"
                    checked={permissions.apps.delete}
                    onChange={(checked) => handlePermissionChange('apps', 'delete', checked)}
                  />
                  <FlagCheckbox
                    label="Edit"
                    checked={permissions.apps.edit}
                    onChange={(checked) => handlePermissionChange('apps', 'edit', checked)}
                  />
                  <FlagCheckbox
                    label="Download"
                    checked={permissions.apps.download}
                    onChange={(checked) => handlePermissionChange('apps', 'download', checked)}
                  />
                  <FlagCheckbox
                    label="Upload"
                    checked={permissions.apps.upload}
                    onChange={(checked) => handlePermissionChange('apps', 'upload', checked)}
                  />
                </div>
                
                <div className='mt-2'>
                  <Dropdown
                    multiple
                    ariaLabel="Allowed apps"
                    placeholder="Select allowed apps"
                    value={permissions.apps.allowed}
                    onChange={(id) =>
                      permissions.apps.allowed.includes(id)
                        ? handleRemoveAllowedItem('apps', id)
                        : handleAllowedItemSelect('apps', id)
                    }
                    options={(Array.isArray(apps) ? apps : []).map((item) => ({
                      value: item.ID,
                      label: item.AppName,
                    }))}
                  />
                  {permissions.apps.allowed.length > 0 && (
                    <div className='mt-2 flex flex-wrap gap-2'>
                      {permissions.apps.allowed.map(id => (
                        <span key={id} className={`${STATUS_BADGE} border-white/15 text-white/85`}>
                          {getNameById(id, 'app')}
                          <button
                            type='button'
                            onClick={() => handleRemoveAllowedItem('apps', id)}
                            className='ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300'
                            aria-label='Remove'
                          >
                            <i className='fas fa-times'></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              
              <div className='mb-4'>
                <h4 className={`${SECTION_LABEL} mb-2`}>Channels</h4>
                <div className='grid grid-cols-2 gap-2'>
                  <FlagCheckbox
                    label="Create"
                    checked={permissions.channels.create}
                    onChange={(checked) => handlePermissionChange('channels', 'create', checked)}
                  />
                  <FlagCheckbox
                    label="Delete"
                    checked={permissions.channels.delete}
                    onChange={(checked) => handlePermissionChange('channels', 'delete', checked)}
                  />
                  <FlagCheckbox
                    label="Edit"
                    checked={permissions.channels.edit}
                    onChange={(checked) => handlePermissionChange('channels', 'edit', checked)}
                  />
                </div>
                
                <div className='mt-2'>
                  <Dropdown
                    multiple
                    ariaLabel="Allowed channels"
                    placeholder="Select allowed channels"
                    value={permissions.channels.allowed}
                    onChange={(id) =>
                      permissions.channels.allowed.includes(id)
                        ? handleRemoveAllowedItem('channels', id)
                        : handleAllowedItemSelect('channels', id)
                    }
                    options={(Array.isArray(channels) ? channels : []).map((item) => ({
                      value: item.ID,
                      label: item.ChannelName,
                    }))}
                  />
                  {permissions.channels.allowed.length > 0 && (
                    <div className='mt-2 flex flex-wrap gap-2'>
                      {permissions.channels.allowed.map(id => (
                        <span key={id} className={`${STATUS_BADGE} border-white/15 text-white/85`}>
                          {getNameById(id, 'channel')}
                          <button
                            type='button'
                            onClick={() => handleRemoveAllowedItem('channels', id)}
                            className='ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300'
                            aria-label='Remove'
                          >
                            <i className='fas fa-times'></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              
              <div className='mb-4'>
                <h4 className={`${SECTION_LABEL} mb-2`}>Platforms</h4>
                <div className='grid grid-cols-2 gap-2'>
                  <FlagCheckbox
                    label="Create"
                    checked={permissions.platforms.create}
                    onChange={(checked) => handlePermissionChange('platforms', 'create', checked)}
                  />
                  <FlagCheckbox
                    label="Delete"
                    checked={permissions.platforms.delete}
                    onChange={(checked) => handlePermissionChange('platforms', 'delete', checked)}
                  />
                  <FlagCheckbox
                    label="Edit"
                    checked={permissions.platforms.edit}
                    onChange={(checked) => handlePermissionChange('platforms', 'edit', checked)}
                  />
                </div>
                
                <div className='mt-2'>
                  <Dropdown
                    multiple
                    ariaLabel="Allowed platforms"
                    placeholder="Select allowed platforms"
                    value={permissions.platforms.allowed}
                    onChange={(id) =>
                      permissions.platforms.allowed.includes(id)
                        ? handleRemoveAllowedItem('platforms', id)
                        : handleAllowedItemSelect('platforms', id)
                    }
                    options={(Array.isArray(platforms) ? platforms : []).map((item) => ({
                      value: item.ID,
                      label: item.PlatformName,
                    }))}
                  />
                  {permissions.platforms.allowed.length > 0 && (
                    <div className='mt-2 flex flex-wrap gap-2'>
                      {permissions.platforms.allowed.map(id => (
                        <span key={id} className={`${STATUS_BADGE} border-white/15 text-white/85`}>
                          {getNameById(id, 'platform')}
                          <button
                            type='button'
                            onClick={() => handleRemoveAllowedItem('platforms', id)}
                            className='ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300'
                            aria-label='Remove'
                          >
                            <i className='fas fa-times'></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              
              <div className='mb-4'>
                <h4 className={`${SECTION_LABEL} mb-2`}>Architectures</h4>
                <div className='grid grid-cols-2 gap-2'>
                  <FlagCheckbox
                    label="Create"
                    checked={permissions.archs.create}
                    onChange={(checked) => handlePermissionChange('archs', 'create', checked)}
                  />
                  <FlagCheckbox
                    label="Delete"
                    checked={permissions.archs.delete}
                    onChange={(checked) => handlePermissionChange('archs', 'delete', checked)}
                  />
                  <FlagCheckbox
                    label="Edit"
                    checked={permissions.archs.edit}
                    onChange={(checked) => handlePermissionChange('archs', 'edit', checked)}
                  />
                </div>
                
                <div className='mt-2'>
                  <Dropdown
                    multiple
                    ariaLabel="Allowed architectures"
                    placeholder="Select allowed architectures"
                    value={permissions.archs.allowed}
                    onChange={(id) =>
                      permissions.archs.allowed.includes(id)
                        ? handleRemoveAllowedItem('archs', id)
                        : handleAllowedItemSelect('archs', id)
                    }
                    options={(Array.isArray(architectures) ? architectures : []).map((item) => ({
                      value: item.ID,
                      label: item.ArchID,
                    }))}
                  />
                  {permissions.archs.allowed.length > 0 && (
                    <div className='mt-2 flex flex-wrap gap-2'>
                      {permissions.archs.allowed.map(id => (
                        <span key={id} className={`${STATUS_BADGE} border-white/15 text-white/85`}>
                          {getNameById(id, 'arch')}
                          <button
                            type='button'
                            onClick={() => handleRemoveAllowedItem('archs', id)}
                            className='ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300'
                            aria-label='Remove'
                          >
                            <i className='fas fa-times'></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
          
          <div className='mt-6 flex justify-end gap-2'>
            <button type='button' onClick={onClose} className={BTN_GHOST}>
              Cancel
            </button>
            <button
              type='button'
              onClick={handleSave}
              disabled={isSaving || !username.trim() || !password.trim()}
              className={`${BTN_PRIMARY} inline-flex items-center gap-2`}
            >
              {isSaving ? (
                <>
                  <i className="fas fa-spinner fa-spin"></i>
                  Creating...
                </>
              ) : (
                'Create user'
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}; 