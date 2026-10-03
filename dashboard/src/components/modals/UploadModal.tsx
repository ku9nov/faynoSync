import React, { useState } from 'react';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { useUploadQuery } from '@/hooks/use-query/useUploadQuery';
import { AdvancedModal } from '@/components/common/AdvancedModal';
import { Dropdown } from '@/components/common/Dropdown';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { getPlatformIcon } from '@/utils/platformIcon';
import {
  FIELD_INPUT,
  FIELD_LABEL,
} from '@/components/common/ui';

interface UploadModalProps {
  onClose: () => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({ onClose }) => {
  const [formData, setFormData] = useState({
    app_name: '',
    version: '',
    channel: '',
    platform: '',
    arch: '',
    publish: false,
    critical: false,
    intermediate: false,
    changelog: '',
    updater: '',
    signature: '',
  });


  const handleOptionClick = (dropdownName: string, value: string) => {
    setFormData(prev => ({ 
      ...prev, 
      [dropdownName]: value,
      // Reset updater when platform changes
      ...(dropdownName === 'platform' && { updater: '', signature: '' }),
      // Reset signature when updater changes
      ...(dropdownName === 'updater' && { signature: '' })
    }));
  };

  const [previewChangelog, setPreviewChangelog] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [files, setFiles] = useState<{ file: File; id: string }[]>([]);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const { apps } = useAppsQuery();
  const { channels } = useChannelQuery();
  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();
  const { upload, isLoading } = useUploadQuery();

  // Get selected platform and its updaters
  const selectedPlatform = platforms.find(p => p.PlatformName === formData.platform);
  const availableUpdaters = selectedPlatform?.Updaters || [];
  const hasMultipleUpdaters = availableUpdaters.length > 1;
  const showUpdaterDropdown = hasMultipleUpdaters && formData.platform;
  
  // Set default updater to 'manual' when dropdown is shown and no updater is selected
  React.useEffect(() => {
    if (showUpdaterDropdown && !formData.updater) {
      setFormData(prev => ({ ...prev, updater: 'manual' }));
    }
  }, [showUpdaterDropdown, formData.updater]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setUploadError(null);
    try {
      const formDataToSend = new FormData();
      
      Object.entries(formData).forEach(([key, value]) => {
        if (value !== '' && key !== 'updater') {
          formDataToSend.append(key, value.toString());
        }
      });
      
      files.forEach(fileInfo => {
        formDataToSend.append('files', fileInfo.file);
      });
      
      const uploadData = {
        app_name: formData.app_name,
        version: formData.version,
        channel: formData.channel,
        platform: formData.platform,
        arch: formData.arch,
        publish: formData.publish,
        critical: formData.critical,
        intermediate: formData.intermediate,
        changelog: formData.changelog,
        files: files.map(f => f.file),
        updater: formData.updater && formData.updater !== 'manual' ? formData.updater : undefined,
        ...(formData.updater === 'tauri' && formData.signature && { signature: formData.signature }),
      };
      
      await upload(uploadData);
      setUploadError(null);
      setIsSuccess(true);
      setTimeout(() => {
        onClose();
      }, 500);
    } catch (error: any) {
      console.error('Upload failed:', error);
      // Extract error message from API response
      let errorMessage = 'Upload failed';
      if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      } else if (error.message) {
        errorMessage = error.message;
      }
      // Set error state to display the message
      setUploadError(errorMessage);
    }
  };

  return (
    <AdvancedModal
      onClose={onClose}
      title="Upload Application"
      onSubmit={handleSubmit}
      submitButtonText="Upload"
      isLoading={isLoading}
      isSuccess={isSuccess}
      successMessage="Files uploaded successfully!"
      error={uploadError ? { error: 'Upload failed', details: uploadError } : null}
      showChangelogPreview={previewChangelog}
      changelogValue={formData.changelog}
      onChangelogChange={(value) => setFormData(prev => ({ ...prev, changelog: value }))}
      onChangelogPreviewToggle={() => setPreviewChangelog(!previewChangelog)}
      fileUploadConfig={{
        multiple: true,
        required: true
      }}
      onFilesChange={setFiles}
      files={files}
    >
      {!Array.isArray(apps) || apps.length === 0 ? (
        <div className="text-theme-primary text-center py-8">
          You don't have created applications, please create application and try again
        </div>
      ) : (
        <>
          <div className="mb-4">
            <label className={FIELD_LABEL}>App Name</label>
            <Dropdown
              ariaLabel="App name"
              placeholder="Select an app"
              value={formData.app_name}
              onChange={(value) => handleOptionClick('app_name', value)}
              options={apps.map((app) => ({ value: app.AppName, label: app.AppName }))}
            />
          </div>

          <div className="mb-4">
            <label className={FIELD_LABEL}>Version</label>
            <input
              type="text"
              name="version"
              value={formData.version}
              onChange={(e) => setFormData(prev => ({ ...prev, version: e.target.value }))}
              className={FIELD_INPUT}
              placeholder="e.g., 0.0.1.0"
              required
            />
          </div>

          {channels.length > 0 && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>Channel</label>
              <Dropdown
                ariaLabel="Channel"
                placeholder="Select a channel"
                value={formData.channel}
                onChange={(value) => handleOptionClick('channel', value)}
                options={channels.map((channel) => ({ value: channel.ChannelName, label: channel.ChannelName }))}
              />
            </div>
          )}

          {platforms.length > 0 && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>Platform</label>
              <Dropdown
                ariaLabel="Platform"
                placeholder="Select a platform"
                value={formData.platform}
                onChange={(value) => handleOptionClick('platform', value)}
                options={platforms.map((platform) => ({
                  value: platform.PlatformName,
                  label: platform.PlatformName,
                  icon: getPlatformIcon(platform.PlatformName),
                }))}
              />
            </div>
          )}

          {showUpdaterDropdown && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>
                Updater
                <span className="ml-2 font-normal text-white/50">
                  (This platform has multiple enabled updaters, select desired updater if necessary)
                </span>
              </label>
              <Dropdown
                ariaLabel="Updater"
                placeholder="manual (default)"
                value={formData.updater}
                onChange={(value) => handleOptionClick('updater', value)}
                options={availableUpdaters.map((u) => ({ value: u.type, label: u.type }))}
              />
            </div>
          )}

          {formData.updater === 'tauri' && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>Signature</label>
              <input
                type="text"
                name="signature"
                value={formData.signature}
                onChange={(e) => setFormData(prev => ({ ...prev, signature: e.target.value }))}
                className={FIELD_INPUT}
                placeholder="Enter signature for Tauri updater"
                required
              />
            </div>
          )}

          {architectures.length > 0 && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>Architecture</label>
              <Dropdown
                ariaLabel="Architecture"
                placeholder="Select an architecture"
                value={formData.arch}
                onChange={(value) => handleOptionClick('arch', value)}
                options={architectures.map((arch) => ({ value: arch.ArchID, label: arch.ArchID }))}
              />
            </div>
          )}

          <div className="mt-2 flex flex-wrap gap-2">
            <FlagCheckbox
              label="Publish"
              tone="green"
              checked={formData.publish}
              onChange={(checked) => setFormData(prev => ({ ...prev, publish: checked }))}
            />
            <FlagCheckbox
              label="Critical"
              tone="red"
              checked={formData.critical}
              onChange={(checked) => setFormData(prev => ({ ...prev, critical: checked }))}
            />
            <FlagCheckbox
              label="Intermediate"
              tone="amber"
              checked={formData.intermediate}
              onChange={(checked) => setFormData(prev => ({ ...prev, intermediate: checked }))}
            />
          </div>
        </>
      )}
    </AdvancedModal>
  );
};