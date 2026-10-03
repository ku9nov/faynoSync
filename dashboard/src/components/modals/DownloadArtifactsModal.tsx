import React, { useState, useEffect } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { Artifact } from '@/hooks/use-query/useAppsQuery';
import axiosInstance from '@/config/axios';
import { copyToClipboard } from '@/utils/clipboard';
import { getPlatformIcon } from '@/utils/platformIcon';
import {
  ACTION_BUTTON,
  ACTION_GROUP,
  BTN_GHOST,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
  ROW_META,
  ROW_TILE,
  ROW_TITLE,
  STATUS_BADGE,
} from '@/components/common/ui';

interface DownloadArtifactsModalProps {
  artifacts: Artifact[];
  onClose: () => void;
}

export const DownloadArtifactsModal: React.FC<DownloadArtifactsModalProps> = ({
  artifacts,
  onClose,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  // Cleanup function to remove any temporary elements
  useEffect(() => {
    return () => {
      const tempElements = document.querySelectorAll('.temp-clipboard-element');
      tempElements.forEach(el => el.remove());
    };
  }, []);

  const backdropProps = useBackdropClose(onClose);

  const handleDownload = (artifact: Artifact) => {
    // First try to fetch the link with authentication
    axiosInstance.get(artifact.link)
      .then(response => {
        // Check if the response is JSON with a download_url
        if (response.data && typeof response.data === 'object' && 'download_url' in response.data) {
          // If it's a JSON with download_url, use that URL
          window.open(response.data.download_url, '_blank', 'noopener,noreferrer');
        } else {
          // Otherwise, it's a direct link to a file, use it directly
          window.open(artifact.link, '_blank', 'noopener,noreferrer');
        }
        onClose();
      })
      .catch((error) => {
        if (error?.response?.status === 404) {
          setCopyError('Download is not available.');
          setTimeout(() => setCopyError(null), 3000);
          return;
        }
        // If there's an error (like 401), it might be a direct link to a public file
        // In that case, just open the link directly
        window.open(artifact.link, '_blank', 'noopener,noreferrer');
        onClose();
      });
  };

  const handleCopyLink = async (link: string, index: number) => {
    setCopyError(null);
    try {
      // First try to fetch the signed URL
      const response = await axiosInstance.get(link);
      
      // Check if the response is JSON with a download_url
      const urlToCopy = response.data && typeof response.data === 'object' && 'download_url' in response.data
        ? response.data.download_url
        : link;
      
      const success = await copyToClipboard(urlToCopy);
      
      if (success) {
        setCopiedIndex(index);
        setTimeout(() => setCopiedIndex(null), 2000);
      } else {
        setCopyError('Failed to copy link. Please try selecting and copying manually.');
        setTimeout(() => setCopyError(null), 3000);
      }
    } catch (err) {
      if ((err as { response?: { status?: number } })?.response?.status === 404) {
        setCopyError('Download is not available.');
        setTimeout(() => setCopyError(null), 3000);
        return;
      }
      // If there's an error, try to copy the original link
      try {
        const success = await copyToClipboard(link);
        if (success) {
          setCopiedIndex(index);
          setTimeout(() => setCopiedIndex(null), 2000);
        } else {
          setCopyError('Failed to copy link. Please try selecting and copying manually.');
          setTimeout(() => setCopyError(null), 3000);
        }
      } catch (clipboardErr) {
        console.error('Failed to copy link:', clipboardErr);
        setCopyError('Failed to copy link. Please try selecting and copying manually.');
        setTimeout(() => setCopyError(null), 3000);
      }
    }
  };

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} flex w-[460px] max-h-[80vh] flex-col overflow-y-auto`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Download artifact</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {copyError && (
          <div className="mb-4 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-2 text-sm text-red-200">
            {copyError}
          </div>
        )}
        <div className="flex-1 space-y-2 overflow-y-auto pr-1">
          {artifacts.map((artifact, index) => (
            <div
              key={index}
              className="cursor-pointer rounded-lg border border-white/15 bg-violet-950/30 p-3 transition-colors hover:bg-violet-950/50"
              onClick={() => handleDownload(artifact)}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span className={ROW_TILE}>
                    <i className={`${getPlatformIcon(artifact.platform)} text-white/90`}></i>
                  </span>
                  <div className="min-w-0">
                    <p className={ROW_TITLE}>{artifact.platform}</p>
                    <div className={ROW_META}>
                      <span>{artifact.arch}</span>
                      <span aria-hidden="true">·</span>
                      <span className="truncate">{artifact.package}</span>
                    </div>
                  </div>
                  {artifact.TufTaskID && (
                    <span
                      className={`${STATUS_BADGE} shrink-0 ${
                        artifact.TufSigned ? 'text-green-300 border-green-500/40' : 'text-red-300 border-red-500/45'
                      }`}
                    >
                      <i className="fas fa-shield-alt text-[11px]"></i>
                      {artifact.TufSigned ? 'signed' : 'unsigned'}
                    </span>
                  )}
                </div>
                <i className="fas fa-download shrink-0 text-green-400"></i>
              </div>
              <div className="mt-3 flex items-center gap-2 rounded-md border border-white/10 bg-violet-950/40 px-2 py-1.5">
                <p className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-white/70">
                  {artifact.link}
                </p>
                <span className={ACTION_GROUP}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCopyLink(artifact.link, index);
                    }}
                    className={`${ACTION_BUTTON} ${
                      copiedIndex === index ? 'text-green-400' : 'text-purple-300 hover:bg-purple-400/20'
                    }`}
                    title={copiedIndex === index ? 'Copied' : 'Copy link'}
                    aria-label={copiedIndex === index ? 'Copied' : 'Copy link'}
                  >
                    <i className={`fas ${copiedIndex === index ? 'fa-check' : 'fa-copy'}`}></i>
                  </button>
                </span>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-6 flex justify-end">
          <button onClick={onClose} className={BTN_GHOST}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
