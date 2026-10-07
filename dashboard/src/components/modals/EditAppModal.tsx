import React, { useState } from 'react';
import axiosInstance from '@/config/axios';
import { AxiosError } from 'axios';
import { BaseModal } from '@/components/common/BaseModal';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { DownloadModeSelector } from '@/components/common/DownloadModeSelector';
import { DownloadMode } from '@/hooks/use-query/useAppsQuery';
import {
  ACTION_BUTTON,
  ACTION_GROUP,
  BTN_GHOST,
  BTN_PRIMARY,
  DROPZONE,
  FIELD_INPUT,
  FIELD_LABEL,
  ROW,
  ROW_META,
  ROW_TILE,
  ROW_TITLE,
} from '@/components/common/ui';

interface EditAppModalProps {
  onClose: () => void;
  onSuccess?: () => void;
  appData: {
    id: string;
    app: string;
    description: string;
    logo?: string;
    tuf?: boolean;
    reports?: boolean;
    cdn?: boolean;
    private?: boolean;
    downloadMode?: DownloadMode;
  };
}

interface ErrorResponse {
  error: string;
  details?: string;
}

export const EditAppModal: React.FC<EditAppModalProps> = ({ onClose, onSuccess, appData }) => {
  const [formData, setFormData] = useState({
    app: appData.app,
    description: appData.description,
    file: null as File | null,
    tuf: appData.tuf || false,
    reports: appData.reports || false,
    cdn: appData.cdn || false,
    downloadMode: appData.downloadMode ?? null,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState<{ error: string; details?: string } | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFormData(prev => ({
        ...prev,
        file,
      }));
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const formDataToSend = new FormData();
      const data = {
        id: appData.id,
        app: formData.app,
        description: formData.description,
        tuf: formData.tuf ? "true" : "false",
        reports: formData.reports ? "true" : "false",
        cdn: formData.cdn ? "true" : "false",
        ...(appData.private && formData.downloadMode && { download_mode: formData.downloadMode }),
      };
      
      formDataToSend.append('data', JSON.stringify(data));
      
      if (formData.file) {
        formDataToSend.append('file', formData.file);
      }

      await axiosInstance.post('/app/update', formDataToSend, {
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
          error: axiosError.response.data.error || 'Failed to update application',
          details: axiosError.response.data.details
        });
      } else {
        setError({
          error: 'Failed to update application',
          details: axiosError.message
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <BaseModal
      title="Edit Application"
      onClose={onClose}
      isLoading={isLoading}
      isSuccess={isSuccess}
      successMessage="Application updated successfully!"
      error={error}
      setError={setError}
      className="w-[500px] max-h-[80vh] overflow-y-auto relative"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
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

        <div>
          <label className={FIELD_LABEL}>Description</label>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
            className={FIELD_INPUT}
            rows={4}
            placeholder="Enter app description"
          />
        </div>

        <div className="mb-6 flex flex-col gap-2">
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
          {!appData.private && (
            <FlagCheckbox
              label="Enable CDN"
              description="Serve artifacts through a CDN edge"
              checked={formData.cdn}
              onChange={(checked) => setFormData(prev => ({ ...prev, cdn: checked }))}
            />
          )}
        </div>

        {appData.private && (
          <DownloadModeSelector
            value={formData.downloadMode}
            onChange={(mode) => setFormData(prev => ({ ...prev, downloadMode: mode }))}
          />
        )}

        <div>
          <label className={FIELD_LABEL}>Logo</label>
          <div className="relative">
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileChange}
              className="hidden"
              id="file-upload"
              accept="image/*"
            />
            <label htmlFor="file-upload" className={DROPZONE}>
              <i className="fas fa-plus"></i>
              Choose a logo
            </label>
          </div>
          {formData.file && (
            <div className={`${ROW} mt-2`}>
              <div className="flex min-w-0 items-center gap-3">
                <span className={ROW_TILE}>
                  <i className="fas fa-image text-white/90"></i>
                </span>
                <div className="min-w-0">
                  <p className={ROW_TITLE}>{formData.file.name}</p>
                  <div className={ROW_META}>
                    <span>{formatFileSize(formData.file.size)}</span>
                  </div>
                </div>
              </div>
              <div className={ACTION_GROUP}>
                <button
                  type="button"
                  onClick={() => setFormData(prev => ({ ...prev, file: null }))}
                  className={`${ACTION_BUTTON} text-red-300 hover:bg-red-500/25`}
                  title="Remove file"
                  aria-label="Remove file"
                >
                  <i className="fas fa-times"></i>
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button
            type="button"
            onClick={onClose}
            disabled={isLoading}
            className={BTN_GHOST}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isLoading}
            className={`${BTN_PRIMARY} flex items-center gap-2`}
          >
            {isLoading ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"></div>
                Updating...
              </>
            ) : (
              'Update'
            )}
          </button>
        </div>
      </form>
    </BaseModal>
  );
}; 