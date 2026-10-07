import React, { useState } from 'react';
import axiosInstance from '@/config/axios';
import { AxiosError } from 'axios';
import { AdvancedModal } from '@/components/common/AdvancedModal';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { DownloadModeSelector } from '@/components/common/DownloadModeSelector';
import { DownloadMode } from '@/hooks/use-query/useAppsQuery';
import {
  FIELD_INPUT,
  FIELD_LABEL,
} from '@/components/common/ui';

interface ErrorResponse {
  error: string;
  details?: string;
}

interface CreateAppModalProps {
  onClose: () => void;
  onSuccess?: () => void;
}

export const CreateAppModal: React.FC<CreateAppModalProps> = ({ onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    app: '',
    description: '',
    private: false,
    tuf: false,
    reports: false,
    cdn: false,
    downloadMode: null as DownloadMode | null,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<{ error: string; details?: string } | null>(null);
  const [files, setFiles] = useState<{ file: File; id: string }[]>([]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const formDataToSend = new FormData();
      const data = {
        app: formData.app,
        description: formData.description,
        ...(formData.private && { private: "true" }),
        ...(formData.private && formData.downloadMode && { download_mode: formData.downloadMode }),
        tuf: formData.tuf ? "true" : "false",
        reports: formData.reports ? "true" : "false",
        cdn: formData.cdn && !formData.private ? "true" : "false",
      };
      
      formDataToSend.append('data', JSON.stringify(data));
      
      if (files.length > 0) {
        formDataToSend.append('file', files[0].file);
      }

      await axiosInstance.post('/app/create', formDataToSend, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setIsSuccess(true);
      if (onSuccess) {
        onSuccess();
      }
      onClose();

    } catch (err) {
      const axiosError = err as AxiosError<ErrorResponse>;
      if (axiosError.response?.data) {
        setError({
          error: axiosError.response.data.error || 'Failed to create',
          details: axiosError.response.data.details
        });
      } else {
        setError({
          error: 'Failed to create',
          details: axiosError.message
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AdvancedModal
      onClose={onClose}
      title="Create Application"
      onSubmit={handleSubmit}
      submitButtonText="Create"
      onSuccess={onSuccess}
      isLoading={isLoading}
      isSuccess={isSuccess}
      successMessage="Application created successfully!"
      error={error}
      fileUploadConfig={{
        accept: "image/*",
        multiple: false,
        label: "Logo",
        required: false
      }}
      onFilesChange={setFiles}
      files={files}
    >
      <div className="mb-4">
        <label className={FIELD_LABEL}>App Name</label>
        <input
          type="text"
          value={formData.app}
          onChange={(e) => setFormData(prev => ({ ...prev, app: e.target.value }))}
          className={FIELD_INPUT}
          required
          placeholder="Enter app name"
        />
      </div>

      <div className="mb-4">
        <label className={FIELD_LABEL}>Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          className={FIELD_INPUT}
          rows={4}
          placeholder="Enter app description"
        />
      </div>

      <div className="mb-2 flex flex-col gap-2">
        <FlagCheckbox
          label="Private app"
          description="Store artifacts in a private bucket"
          checked={formData.private}
          onChange={(checked) => setFormData(prev => ({ ...prev, private: checked }))}
        />
        {formData.private && (
          <div className="mb-2 ml-4">
            <DownloadModeSelector
              value={formData.downloadMode}
              onChange={(mode) => setFormData(prev => ({ ...prev, downloadMode: mode }))}
              hint="Leave unselected to use the server default"
            />
          </div>
        )}
        <FlagCheckbox
          label="Enable TUF"
          description="Sign this application's artifacts with The Update Framework"
          checked={formData.tuf}
          onChange={(checked) => setFormData(prev => ({ ...prev, tuf: checked }))}
        />
        <FlagCheckbox
          label="Enable reports"
          description="Collect update reports for this application"
          checked={formData.reports}
          onChange={(checked) => setFormData(prev => ({ ...prev, reports: checked }))}
        />
        {!formData.private && (
          <FlagCheckbox
            label="Enable CDN"
            description="Serve artifacts through a CDN edge"
            checked={formData.cdn}
            onChange={(checked) => setFormData(prev => ({ ...prev, cdn: checked }))}
          />
        )}
      </div>
    </AdvancedModal>
  );
}; 