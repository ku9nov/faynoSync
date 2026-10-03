import React, { useState, useEffect } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import ReactDOM from 'react-dom';
import { useUsersQuery } from '@/hooks/use-query/useUsersQuery';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { useAdminUpdateQuery } from '@/hooks/use-query/useAdminUpdateQuery';
import {
  BTN_GHOST,
  BTN_PRIMARY,
  FIELD_INPUT,
  FIELD_LABEL,
  MODAL_CLOSE,
  MODAL_SURFACE,
  SECTION_LABEL,
  STATUS_BADGE,
  STATUS_DOT,
} from '@/components/common/ui';

interface ProfileModalProps {
  onClose: () => void;
}

export const ProfileModal: React.FC<ProfileModalProps> = ({ onClose }) => {
  const { data: userData, isLoading: userLoading, refetch: refetchUser } = useUsersQuery();
  const { apps, refetch: refetchApps } = useAppsQuery();
  const { channels, refetch: refetchChannels } = useChannelQuery();
  const { platforms, refetch: refetchPlatforms } = usePlatformQuery();
  const { architectures, refetch: refetchArchitectures } = useArchitectureQuery();
  const { updateAdmin, isLoading: isUpdatingAdmin } = useAdminUpdateQuery();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState<string | null>(null);

  // Refresh data when modal is opened
  useEffect(() => {
    refetchUser();
    refetchApps();
    refetchChannels();
    refetchPlatforms();
    refetchArchitectures();

  }, [refetchUser, refetchApps, refetchChannels, refetchPlatforms, refetchArchitectures]);

  const backdropProps = useBackdropClose(onClose);

  const generatePassword = () => {
    const length = 32;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let generatedPassword = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      generatedPassword += charset[randomIndex];
    }
    
    setNewPassword(generatedPassword);
    setConfirmPassword(generatedPassword);
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

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);

    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters long');
      return;
    }

    try {
      if (!userData) {
        setPasswordError('User data not available');
        return;
      }

      await updateAdmin({
        id: userData.id,
        username: userData.username,
        password: newPassword
      });

      setPasswordSuccess('Password changed successfully');
      setNewPassword('');
      setConfirmPassword('');
      
      // Close the modal after a short delay to allow the user to see the success message
      setTimeout(() => {
        onClose();
      }, 1500);
    } catch (error: any) {
      setPasswordError(error.message || 'Failed to change password');
    }
  };

  // Helper function to get name by ID
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

  if (userLoading) {
    return (
      <div className="fixed inset-0 bg-black/60 flex items-center justify-center modal-overlay-high">
        <div className={`${MODAL_SURFACE} w-[500px] max-h-[80vh] overflow-y-auto relative`}>
          <div className="flex justify-center items-center h-40">
            <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-theme-primary"></div>
          </div>
        </div>
      </div>
    );
  }

  return ReactDOM.createPortal(
    <div 
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-[11000] overflow-y-auto min-h-screen p-4"
      {...backdropProps}
    >
      <div className={`${MODAL_SURFACE} w-full max-w-[600px] max-h-[90vh] overflow-y-auto relative`}
        onClick={e => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className={`${MODAL_CLOSE} absolute top-4 right-4`}
          aria-label="Close"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        <h2 className="mb-6 text-2xl font-bold text-theme-primary">Profile</h2>

        {userData && (
          <div className="mb-6">
            <div className="flex items-center mb-4">
              <div className="mr-4 flex h-16 w-16 items-center justify-center rounded-full border border-white/15 bg-violet-950/40">
                <span className="text-xl font-extrabold tracking-tight text-theme-primary">
                  {userData.username.slice(0, 2).toUpperCase()}
                </span>
              </div>
              <div>
                <h3 className="text-xl font-bold text-theme-primary">{userData.username}</h3>
                <span
                  className={`${STATUS_BADGE} mt-1 px-2 py-0.5 text-[11px] ${
                    userData.is_admin
                      ? 'text-amber-300 border-amber-500/45'
                      : 'text-violet-300 border-violet-400/50'
                  }`}
                >
                  <span className={`${STATUS_DOT} ${userData.is_admin ? 'bg-amber-500' : 'bg-violet-400'}`}></span>
                  {userData.is_admin ? 'Administrator' : 'Team user'}
                </span>
                {!userData.is_admin && userData.owner && (
                  <p className="text-sm text-white/55">Owner: {userData.owner}</p>
                )}
              </div>
            </div>

            {userData.is_admin ? (
              <div className="mb-6">
                <h3 className={`${SECTION_LABEL} mb-3`}>Change password</h3>
                <form onSubmit={handlePasswordChange}>
                  <div className="mb-3">
                    <label className={FIELD_LABEL}>New password</label>
                    <div className="flex gap-2">
                      <input
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className={FIELD_INPUT}
                        required
                      />
                      <button
                        type="button"
                        onClick={generatePassword}
                        className={`${BTN_GHOST} shrink-0`}
                      >
                        Generate
                      </button>
                      {newPassword && (
                        <button
                          type="button"
                          onClick={() => copyToClipboard(newPassword)}
                          className={`${BTN_GHOST} shrink-0`}
                          aria-label="Copy password"
                        >
                          <i className="fas fa-copy"></i>
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="mb-3">
                    <label className={FIELD_LABEL}>Confirm new password</label>
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className={FIELD_INPUT}
                      required
                    />
                  </div>
                  {passwordError && (
                    <div className="mb-3 text-sm text-red-300">{passwordError}</div>
                  )}
                  {passwordSuccess && (
                    <div className="mb-3 text-sm text-green-300">{passwordSuccess}</div>
                  )}
                  {copySuccess && (
                    <div className="mb-3 text-sm text-green-300">{copySuccess}</div>
                  )}
                  <button
                    type="submit"
                    className={`${BTN_PRIMARY} mt-2 inline-flex items-center gap-2`}
                    disabled={isUpdatingAdmin}
                  >
                    {isUpdatingAdmin ? (
                      <>
                        <i className="fas fa-spinner fa-spin"></i>
                        Changing Password...
                      </>
                    ) : (
                      'Change Password'
                    )}
                  </button>
                </form>
              </div>
            ) : userData.permissions && (
              <>
                <div className="mb-6">
                  <h3 className={`${SECTION_LABEL} mb-3`}>Permissions</h3>
                  <div className="overflow-x-auto">
                    <table className="min-w-full overflow-hidden rounded-lg border border-white/15 bg-violet-950/30">
                      <thead>
                        <tr className="bg-white/10 text-left text-[10.5px] font-bold uppercase tracking-[0.09em] text-white/70">
                          <th className="px-4 py-2 text-left">Resource</th>
                          <th className="px-4 py-2 text-left">Create</th>
                          <th className="px-4 py-2 text-left">Edit</th>
                          <th className="px-4 py-2 text-left">Delete</th>
                          <th className="px-4 py-2 text-left">Allowed Items</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(userData.permissions).map(([resource, permissions]: [string, any]) => (
                          <tr key={resource} className="border-t border-white/10">
                            <td className="px-4 py-2 text-theme-primary font-medium">{resource}</td>
                            <td className="px-4 py-2 text-theme-primary">
                              {permissions.Create ? (
                                <i className="fas fa-check text-green-400"></i>
                              ) : (
                                <i className="fas fa-times text-red-300"></i>
                              )}
                            </td>
                            <td className="px-4 py-2 text-theme-primary">
                              {permissions.Edit ? (
                                <i className="fas fa-check text-green-400"></i>
                              ) : (
                                <i className="fas fa-times text-red-300"></i>
                              )}
                            </td>
                            <td className="px-4 py-2 text-theme-primary">
                              {permissions.Delete ? (
                                <i className="fas fa-check text-green-400"></i>
                              ) : (
                                <i className="fas fa-times text-red-300"></i>
                              )}
                            </td>
                            <td className="px-4 py-2 text-theme-primary">
                              {permissions.Allowed && permissions.Allowed.length > 0 ? (
                                <div className="max-h-20 overflow-y-auto">
                                  {permissions.Allowed.map((id: string) => {
                                    let type: 'app' | 'channel' | 'platform' | 'arch' = 'app';
                                    if (resource === 'Channels') type = 'channel';
                                    if (resource === 'Platforms') type = 'platform';
                                    if (resource === 'Archs') type = 'arch';
                                    
                                    return (
                                      <div key={id} className="text-sm">
                                        {getNameById(id, type)}
                                      </div>
                                    );
                                  })}
                                </div>
                              ) : (
                                <span className="text-white/45">None</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                
                {userData.permissions.Apps && (
                  <div className="mb-6">
                    <h3 className={`${SECTION_LABEL} mb-3`}>File actions</h3>
                    <div className="rounded-lg border border-white/15 bg-violet-950/30 p-4">
                      <div className="flex items-center mb-2">
                        <span className="mr-2 text-sm font-semibold text-white/70">Upload:</span>
                        <span className="text-theme-modal-text">
                          {userData.permissions.Apps.Upload ? (
                            <i className="fas fa-check text-green-400"></i>
                          ) : (
                            <i className="fas fa-times text-red-300"></i>
                          )}
                        </span>
                      </div>
                      <div className="flex items-center">
                        <span className="mr-2 text-sm font-semibold text-white/70">Download:</span>
                        <span className="text-theme-modal-text">
                          {userData.permissions.Apps.Download ? (
                            <i className="fas fa-check text-green-400"></i>
                          ) : (
                            <i className="fas fa-times text-red-300"></i>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>,
    document.body
  );
}; 