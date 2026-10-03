import React from 'react';
import { ChangelogEntry } from '@/hooks/use-query/useAppsQuery';
import ReactMarkdown from 'react-markdown';
import { BTN_GHOST, MARKDOWN_PREVIEW, MODAL_SURFACE, MODAL_TITLE } from '@/components/common/ui';

interface ChangelogModalProps {
  appName: string;
  version: string;
  changelog: ChangelogEntry[];
  onClose: () => void;
}

export const ChangelogModal: React.FC<ChangelogModalProps> = ({
  appName,
  version,
  changelog,
  onClose,
}) => {
  const currentVersionChangelog = changelog.find(entry => entry.Version === version);

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-start sm:items-center justify-center z-[11000] p-4 overflow-y-auto"
      onClick={onClose}
    >
      <div
        className={`${MODAL_SURFACE} w-full max-w-[800px] max-h-[calc(100vh-2rem)] flex flex-col my-auto`}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className={`${MODAL_TITLE} mb-1`}>Changelog</h2>
        <p className="mb-4 text-sm text-white/70">
          {appName} v{version}
          {currentVersionChangelog && (
            <> · {new Date(currentVersionChangelog.Date).toLocaleDateString()}</>
          )}
        </p>
        <div className="mb-4 min-h-0 overflow-y-auto">
          {currentVersionChangelog ? (
            <div className={MARKDOWN_PREVIEW}>
              <ReactMarkdown>{currentVersionChangelog.Changes || 'No changes description'}</ReactMarkdown>
            </div>
          ) : (
            <p className="text-sm text-white/60">No changelog information available for this version</p>
          )}
        </div>
        <div className="flex justify-end">
          <button onClick={onClose} className={BTN_GHOST}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
