import React, { useRef } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import ReactMarkdown from 'react-markdown';
import { ModalFeedback } from './ModalFeedback';
import {
  ACTION_BUTTON,
  ACTION_GROUP,
  BTN_GHOST,
  BTN_PRIMARY,
  DROPZONE,
  FIELD_INPUT,
  FIELD_LABEL,
  MARKDOWN_PREVIEW,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
  ROW,
  ROW_META,
  ROW_TILE,
  ROW_TITLE,
  SEGMENTED_GROUP,
  segmentedButton,
} from './ui';

interface FileInfo {
  file: File;
  id: string;
}

interface AdvancedModalProps {
  onClose: () => void;
  title: string;
  onSubmit: (formData: any) => Promise<void>;
  children: React.ReactNode;
  submitButtonText?: string;
  onSuccess?: () => void;
  isLoading?: boolean;
  isSuccess?: boolean;
  successMessage?: string;
  error?: { error: string; details?: string } | null;
  showChangelogPreview?: boolean;
  changelogValue?: string;
  onChangelogChange?: (value: string) => void;
  onChangelogPreviewToggle?: () => void;
  fileUploadConfig?: {
    accept?: string;
    multiple?: boolean;
    label?: string;
    required?: boolean;
  };
  onFilesChange?: (files: FileInfo[]) => void;
  files?: FileInfo[];
}

export const AdvancedModal: React.FC<AdvancedModalProps> = ({
  onClose,
  title,
  onSubmit,
  children,
  submitButtonText = 'Submit',
  onSuccess,
  isLoading = false,
  isSuccess = false,
  successMessage = 'Operation completed successfully!',
  error,
  showChangelogPreview = false,
  changelogValue = '',
  onChangelogChange,
  onChangelogPreviewToggle,
  fileUploadConfig,
  onFilesChange,
  files = [],
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const backdropProps = useBackdropClose(onClose, !isLoading);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && onFilesChange) {
      const newFiles = Array.from(e.target.files).map(file => ({
        file,
        id: Math.random().toString(36).substring(2, 9)
      }));
      onFilesChange([...files, ...newFiles]);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const removeFile = (idToRemove: string) => {
    if (onFilesChange) {
      onFilesChange(files.filter(file => file.id !== idToRemove));
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
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-[500px] max-h-[80vh] overflow-y-auto relative`}>
        <ModalFeedback
          isLoading={isLoading}
          isSuccess={isSuccess}
          successMessage={successMessage}
          error={error}
        />
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>{title}</h2>
          <button onClick={onClose} className={MODAL_CLOSE} disabled={isLoading} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={(e) => {
          e.preventDefault();
          onSubmit(e);
          if (onSuccess) {
            onSuccess();
          }
        }}>
          {children}
          
          {fileUploadConfig && (
            <div className="mb-4">
              <label className={FIELD_LABEL}>{fileUploadConfig.label || 'Files'}</label>
              <input
                ref={fileInputRef}
                type="file"
                multiple={fileUploadConfig.multiple}
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
                accept={fileUploadConfig.accept}
                required={fileUploadConfig.required && files.length === 0}
              />
              <label htmlFor="file-upload" className={DROPZONE}>
                <i className="fas fa-plus"></i>
                Choose files to upload
              </label>
              {files.length > 0 && (
                <div className="mt-2 space-y-2">
                  {files.map((fileInfo) => (
                    <div key={fileInfo.id} className={ROW}>
                      <div className="flex min-w-0 items-center gap-3">
                        <span className={ROW_TILE}>
                          <i className="fas fa-file text-white/90"></i>
                        </span>
                        <div className="min-w-0">
                          <p className={ROW_TITLE}>{fileInfo.file.name}</p>
                          <div className={ROW_META}>
                            <span>{formatFileSize(fileInfo.file.size)}</span>
                          </div>
                        </div>
                      </div>
                      <div className={ACTION_GROUP}>
                        <button
                          type="button"
                          onClick={() => removeFile(fileInfo.id)}
                          className={`${ACTION_BUTTON} text-red-300 hover:bg-red-500/25`}
                          title="Remove file"
                          aria-label="Remove file"
                        >
                          <i className="fas fa-times"></i>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {showChangelogPreview !== undefined && onChangelogChange && (
            <div className="mb-4">
              <div className="mb-2 flex items-center justify-between gap-2">
                <label className="text-xs font-semibold text-white/70">Changelog</label>
                <span className={SEGMENTED_GROUP}>
                  <button
                    type="button"
                    onClick={onChangelogPreviewToggle}
                    aria-pressed={!showChangelogPreview}
                    className={segmentedButton(!showChangelogPreview)}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={onChangelogPreviewToggle}
                    aria-pressed={showChangelogPreview}
                    className={segmentedButton(showChangelogPreview, true)}
                  >
                    Preview
                  </button>
                </span>
              </div>
              {showChangelogPreview ? (
                <div className={MARKDOWN_PREVIEW}>
                  <ReactMarkdown>{changelogValue}</ReactMarkdown>
                </div>
              ) : (
                <textarea
                  value={changelogValue}
                  onChange={(e) => onChangelogChange(e.target.value)}
                  className={`${FIELD_INPUT} font-mono text-sm`}
                  rows={4}
                  placeholder="# Changes in this version&#10;- Added new feature&#10;- Fixed bug"
                />
              )}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} disabled={isLoading} className={BTN_GHOST}>
              Cancel
            </button>
            <button type="submit" disabled={isLoading} className={`${BTN_PRIMARY} flex items-center gap-2`}>
              {isLoading ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"></div>
                  Processing...
                </>
              ) : (
                submitButtonText
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}; 