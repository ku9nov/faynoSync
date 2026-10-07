import React, { useState, useEffect } from 'react';
import axiosInstance from '@/config/axios';
import { copyToClipboard } from '@/utils/clipboard';

// The icons sit on the purple->orange field, where a red glyph drops to 1.09:1
// against the orange end — invisible. Grouping them on a dark scrim lifts red-300
// to 4.80:1, so delete can finally read as destructive instead of white.
const ACTION_GROUP =
  'inline-flex items-center gap-px flex-shrink-0 relative rounded-lg p-0.5 bg-violet-950/50 border border-white/20';
const ACTION_BUTTON = 'px-2 py-1.5 rounded-md transition-colors duration-200 flex-shrink-0';

interface ActionIconsProps {
  onDownload: () => void;
  onEdit: () => void;
  onDelete: () => void;
  showDownload?: boolean;
  artifactLink?: string;
}

export const ActionIcons: React.FC<ActionIconsProps> = ({
  onDownload,
  onEdit,
  onDelete,
  showDownload = true,
  artifactLink,
}) => {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState<string | null>(null);

  // Cleanup function to remove any temporary elements
  useEffect(() => {
    return () => {
      const tempElements = document.querySelectorAll('.temp-clipboard-element');
      tempElements.forEach(el => el.remove());
    };
  }, []);

  const handleCopyLink = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setCopyError(null);
    if (artifactLink) {
      try {
        // First try to fetch the signed URL
        const response = await axiosInstance.get(artifactLink);
        
        // Check if the response is JSON with a download_url
        const urlToCopy = response.data && typeof response.data === 'object' && 'download_url' in response.data
          ? response.data.download_url
          : artifactLink;
        
        const success = await copyToClipboard(urlToCopy);
        
        if (success) {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } else {
          setCopyError('Failed to copy link. Please try selecting and copying manually.');
          setTimeout(() => setCopyError(null), 3000);
        }
      } catch (err) {
        // If there's an error, try to copy the original link
        try {
          const success = await copyToClipboard(artifactLink);
          if (success) {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
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
    }
  };

  return (
    <div className={ACTION_GROUP}>
      {copyError && (
        <div className="absolute bottom-full mb-2 p-2 bg-red-500 bg-opacity-20 border border-red-500 rounded text-red-500 text-sm whitespace-nowrap">
          {copyError}
        </div>
      )}
      {showDownload && (
        <>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDownload();
            }}
            className={`${ACTION_BUTTON} text-green-400 hover:bg-green-500/20`}
            title="Download"
            aria-label="Download"
          >
            <i className="fas fa-download"></i>
          </button>
          {artifactLink && (
            <button
              onClick={handleCopyLink}
              className={`${ACTION_BUTTON} text-purple-300 hover:bg-purple-400/20`}
              title={copied ? "Copied!" : "Copy link"}
              aria-label={copied ? "Copied" : "Copy link"}
            >
              <i className={`fas ${copied ? 'fa-check' : 'fa-copy'}`}></i>
            </button>
          )}
        </>
      )}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onEdit();
        }}
        className={`${ACTION_BUTTON} text-gray-200 hover:bg-white/15`}
        title="Edit"
        aria-label="Edit"
      >
        <i className="fas fa-edit"></i>
      </button>
      <button
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        className={`${ACTION_BUTTON} text-red-300 hover:bg-red-500/25`}
        title="Delete"
        aria-label="Delete"
      >
        <i className="fas fa-trash"></i>
      </button>
    </div>
  );
}; 