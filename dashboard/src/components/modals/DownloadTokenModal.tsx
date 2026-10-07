import React, { useState } from 'react';
import { BaseModal } from '@/components/common/BaseModal';
import { copyToClipboard } from '@/utils/clipboard';
import { ACTION_BUTTON, ACTION_GROUP, BTN_GHOST, NOTE_WARNING } from '@/components/common/ui';

interface DownloadTokenModalProps {
  token: string;
  channelName: string;
  replacedExisting: boolean;
  onClose: () => void;
}

export const DownloadTokenModal: React.FC<DownloadTokenModalProps> = ({
  token,
  channelName,
  replacedExisting,
  onClose,
}) => {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);

  const handleCopy = async () => {
    const success = await copyToClipboard(token);
    setCopied(success);
    setCopyError(!success);
    if (success) {
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <BaseModal title="Download token" onClose={onClose} className="w-[500px] max-w-[95vw]">
      <p className="mb-3 text-sm text-white/70">
        Channel: <span className="font-semibold text-theme-primary">{channelName}</span>
      </p>

      <div className={`${NOTE_WARNING} mb-4 items-start`}>
        <i className="fas fa-exclamation-triangle mt-0.5"></i>
        <div className="space-y-1">
          <p>Copy this token now. It cannot be shown again.</p>
          {replacedExisting && <p>The previous token for this channel has stopped working.</p>}
        </div>
      </div>

      <div className="flex items-center gap-2 rounded-md border border-white/10 bg-violet-950/40 px-2 py-1.5">
        <p className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-white/95">{token}</p>
        <span className={ACTION_GROUP}>
          <button
            type="button"
            onClick={handleCopy}
            className={`${ACTION_BUTTON} ${copied ? 'text-green-400' : 'text-purple-300 hover:bg-purple-400/20'}`}
            title={copied ? 'Copied' : 'Copy token'}
            aria-label={copied ? 'Copied' : 'Copy token'}
          >
            <i className={`fas ${copied ? 'fa-check' : 'fa-copy'}`}></i>
          </button>
        </span>
      </div>
      {copyError && <p className="mt-2 text-xs text-red-300">Failed to copy. Select the token and copy it manually.</p>}

      <p className="mt-4 text-xs text-white/55">
        Clients send this token in the <span className="font-mono text-white/80">X-Download-Token</span> header.
      </p>

      <div className="mt-6 flex justify-end">
        <button type="button" onClick={onClose} className={BTN_GHOST}>
          Done
        </button>
      </div>
    </BaseModal>
  );
};
