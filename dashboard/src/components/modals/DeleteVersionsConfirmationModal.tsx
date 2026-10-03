import React from 'react';
import { useBackdropClose } from '@/hooks/useBackdropClose';
import { BulkDeleteOutcome } from '@/hooks/use-query/useAppsQuery';
import { copyToClipboard } from '@/utils/clipboard';
import {
  BTN_DANGER,
  BTN_GHOST,
  FIELD_INPUT,
  MODAL_CLOSE,
  MODAL_HEADER,
  MODAL_OVERLAY,
  MODAL_SURFACE,
  MODAL_TITLE,
  SECTION_LABEL,
} from '@/components/common/ui';

export type SelectedVersion = {
  id: string;
  version: string;
  channel: string;
};

interface DeleteVersionsConfirmationModalProps {
  appName: string;
  versions: SelectedVersion[];
  onClose: () => void;
  onConfirm: (
    ids: string[],
    onProgress: (done: number, total: number) => void,
  ) => Promise<BulkDeleteOutcome>;
}

export const DeleteVersionsConfirmationModal: React.FC<DeleteVersionsConfirmationModalProps> = ({
  appName,
  versions,
  onClose,
  onConfirm,
}) => {
  // The parent prunes its selection as chunks land, so the list is frozen on open -
  // otherwise the report would count against a set that shrank under it.
  const [items] = React.useState(versions);
  const [confirmationText, setConfirmationText] = React.useState('');
  const [progress, setProgress] = React.useState<number | null>(null);
  const [outcome, setOutcome] = React.useState<BulkDeleteOutcome | null>(null);
  const [copied, setCopied] = React.useState(false);

  const isRunning = progress !== null && outcome === null;
  const backdropProps = useBackdropClose(onClose, !isRunning);

  const grouped = React.useMemo(() => {
    const byChannel = new Map<string, string[]>();
    items.forEach(({ version, channel }) => {
      const key = channel || 'no channel';
      byChannel.set(key, [...(byChannel.get(key) || []), version]);
    });
    return [...byChannel.entries()];
  }, [items]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmationText !== appName || isRunning) {
      return;
    }

    setProgress(0);
    const result = await onConfirm(items.map(v => v.id), (done) => setProgress(done));

    if (result.error || result.orphanedLinks.length > 0) {
      setOutcome(result);
      return;
    }
    onClose();
  };

  const handleCopyLinks = async () => {
    if (!outcome || outcome.orphanedLinks.length === 0) {
      return;
    }
    if (await copyToClipboard(outcome.orphanedLinks.join('\n'))) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className={MODAL_OVERLAY} {...backdropProps}>
      <div className={`${MODAL_SURFACE} w-[32rem] max-w-[calc(100vw-2rem)]`}>
        <div className={MODAL_HEADER}>
          <h2 className={MODAL_TITLE}>{outcome ? 'Deletion report' : 'Delete confirmation'}</h2>
          <button onClick={onClose} className={MODAL_CLOSE} aria-label="Close" disabled={isRunning}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {outcome ? (
          <>
            <p className="mb-4 text-sm text-white/85">
              Deleted {outcome.deletedIds.length} of {items.length} version
              {items.length === 1 ? '' : 's'} of "{appName}".
            </p>

            {outcome.error && (
              <div className="mb-4 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-3 text-sm text-red-200">
                <p className="break-words">{outcome.error}</p>
                {outcome.remainingIds.length > 0 && (
                  <p className="mt-2 text-white/70">
                    {outcome.remainingIds.length} version
                    {outcome.remainingIds.length === 1 ? ' was' : 's were'} left untouched.
                  </p>
                )}
              </div>
            )}

            {outcome.orphanedLinks.length > 0 && (
              <div className="mb-6">
                <div className="mb-2 flex items-center gap-3">
                  <p className={SECTION_LABEL}>
                    {outcome.orphanedLinks.length} orphaned artifact
                    {outcome.orphanedLinks.length === 1 ? '' : 's'}
                  </p>
                  <button
                    type="button"
                    onClick={handleCopyLinks}
                    className="shrink-0 rounded-md border border-white/25 px-2 py-1 text-xs font-semibold text-theme-primary transition-colors hover:bg-white/10"
                  >
                    {copied ? 'Copied' : 'Copy all'}
                  </button>
                </div>
                <p className="mb-2 text-sm text-amber-300">
                  The versions are gone, but these files stayed in the bucket and need manual cleanup.
                </p>
                <div className="max-h-40 overflow-y-auto rounded-lg border border-white/15 bg-violet-950/30 p-3">
                  {outcome.orphanedLinks.map(link => (
                    <p key={link} className="mb-1 break-all font-mono text-[11.5px] text-white/80 last:mb-0">
                      {link}
                    </p>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end">
              <button type="button" onClick={onClose} className={BTN_GHOST}>
                Close
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={handleSubmit}>
            <p className="mb-4 flex items-start gap-3 rounded-lg border border-red-500/45 bg-violet-950/40 px-3 py-3 text-sm text-red-200">
              <i className="fas fa-exclamation-triangle mt-0.5"></i>
              <span>
                To delete {items.length} version{items.length === 1 ? '' : 's'} of "{appName}"
                please enter the application name:
              </span>
            </p>

            <div className="mb-4 max-h-48 overflow-y-auto rounded-lg border border-white/15 bg-violet-950/30 p-3">
              {grouped.map(([channel, channelVersions]) => (
                <div key={channel} className="mb-3 last:mb-0">
                  <p className={SECTION_LABEL}>
                    {channel}
                    <span className="font-mono normal-case tracking-normal">{channelVersions.length}</span>
                  </p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {channelVersions.map(version => (
                      <span
                        key={`${channel}-${version}`}
                        className="rounded-md border border-white/15 bg-violet-950/50 px-2 py-0.5 font-mono text-[11.5px] text-theme-primary"
                      >
                        {version}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="mb-6">
              <input
                type="text"
                value={confirmationText}
                onChange={(e) => setConfirmationText(e.target.value)}
                className={FIELD_INPUT}
                placeholder="Enter application name"
                disabled={isRunning}
              />
            </div>

            <div className="flex items-center justify-end gap-3">
              {isRunning && (
                <span className="mr-auto text-sm text-white/70">
                  Deleting {progress} of {items.length}...
                </span>
              )}
              <button type="button" onClick={onClose} className={BTN_GHOST} disabled={isRunning}>
                Cancel
              </button>
              <button
                type="submit"
                disabled={confirmationText !== appName || isRunning}
                className={BTN_DANGER}
              >
                Delete {items.length}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
