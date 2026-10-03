import React, { useState } from 'react';
import { useBackdropClose } from '../../hooks/useBackdropClose';
import { ReportGroup, ReportBlob, useReportBlobsQuery } from '@/hooks/use-query/useReportsQuery';
import { copyToClipboard } from '@/utils/clipboard';
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
  STATUS_BADGE,
} from '@/components/common/ui';

interface ReportBlobsModalProps {
  group: ReportGroup;
  onClose: () => void;
}

const formatBytes = (bytes: number) => {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${exponent === 0 ? value : value.toFixed(1)} ${units[exponent]}`;
};

const formatDateTime = (value: string) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const day = date.getDate();
  const month = date.toLocaleString('en-US', { month: 'short' });
  const year = date.getFullYear();
  const hours = date.getHours().toString().padStart(2, '0');
  const minutes = date.getMinutes().toString().padStart(2, '0');
  return `${day} ${month} ${year}, ${hours}:${minutes}`;
};

const formatLabel = (value: string) =>
  value
    .split('_')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

export const ReportBlobsModal: React.FC<ReportBlobsModalProps> = ({ group, onClose }) => {
  const { blobs, isLoading } = useReportBlobsQuery(group.group_hash);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  const backdropProps = useBackdropClose(onClose);

  const handleCopyLink = async (blob: ReportBlob) => {
    setCopyError(null);
    const success = await copyToClipboard(blob.url);
    if (success) {
      setCopiedId(blob.id);
      setTimeout(() => setCopiedId(null), 2000);
    } else {
      setCopyError('Failed to copy link. Please try selecting and copying manually.');
      setTimeout(() => setCopyError(null), 3000);
    }
  };

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} flex w-full max-w-2xl max-h-[80vh] flex-col overflow-y-auto`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>Report details</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <p className="mb-5 text-sm text-white/70">
          {group.application.name} v{group.application.version} · {formatLabel(group.event.type)} / {formatLabel(group.event.reason)}
        </p>

        {copyError && (
          <div className="mb-4 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-2 text-sm text-red-200">
            {copyError}
          </div>
        )}

        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-white/25 border-t-white"></div>
          </div>
        ) : blobs.length === 0 ? (
          <div className="flex h-40 items-center justify-center">
            <p className="text-sm text-white/60">No detail blobs available for this group</p>
          </div>
        ) : (
          <div className="flex-1 space-y-2 overflow-y-auto pr-1">
            {blobs.map((blob) => (
              <div key={blob.id} className="rounded-lg border border-white/15 bg-violet-950/30 p-4">
                <div className="mb-2 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="break-all font-mono text-sm text-theme-primary">{blob.storage.key}</p>
                    <div className={`${ROW_META} mt-1`}>
                      <span>{blob.storage.content_type}</span>
                      <span aria-hidden="true">·</span>
                      <span>{blob.storage.encoding}</span>
                      <span aria-hidden="true">·</span>
                      <span>{formatBytes(blob.storage.compressed_size)}</span>
                      {blob.storage.decompressed_size > blob.storage.compressed_size && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span>{formatBytes(blob.storage.decompressed_size)} decompressed</span>
                        </>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-white/50">
                      Created {formatDateTime(blob.created_at)} · Link expires {formatDateTime(blob.expires_at)}
                    </p>
                  </div>
                  <span className={`${STATUS_BADGE} shrink-0 border-violet-400/50 text-violet-200`}>
                    {blob.storage.driver}
                  </span>
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <a
                    href={blob.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`${BTN_GHOST} inline-flex items-center gap-2 py-1.5 text-sm`}
                  >
                    <i className="fas fa-download text-green-400"></i>
                    Download
                  </a>
                  <span className={ACTION_GROUP}>
                    <button
                      type="button"
                      onClick={() => handleCopyLink(blob)}
                      className={`${ACTION_BUTTON} ${
                        copiedId === blob.id ? 'text-green-400' : 'text-purple-300 hover:bg-purple-400/20'
                      }`}
                      title="Copy presigned link"
                      aria-label="Copy presigned link"
                    >
                      <i className={`fas ${copiedId === blob.id ? 'fa-check' : 'fa-copy'}`}></i>
                    </button>
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="mt-6 flex justify-end">
          <button onClick={onClose} className={BTN_GHOST}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
