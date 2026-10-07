import React, { useState } from 'react';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery, Updater } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { useToast } from '@/hooks/useToast';
import { BaseModal } from '@/components/common/BaseModal';
import { Dropdown } from '@/components/common/Dropdown';
import { FlagCheckbox } from '@/components/common/FlagCheckbox';
import { getPlatformIcon } from '@/utils/platformIcon';
import { copyToClipboard } from '@/utils/clipboard';
import { env } from '@/config/env';
import {
  generatePresignedUploadScript,
  PRESIGNED_UPLOADS_DOCS_URL,
} from '@/utils/generatePresignedUploadScript';
import { BTN_GHOST, BTN_PRIMARY, FIELD_LABEL, NOTE_WARNING } from '@/components/common/ui';

// Mirrors the server: these updaters publish a public feed, so private apps reject them.
const PRIVATE_BLOCKED_UPDATERS = ['velopack', 'sparkle', 'electron-builder', 'squirrel_windows'];

const HINT = 'text-xs text-white/60 leading-relaxed';

interface CiUploadCommandModalProps {
  appName: string;
  isTuf: boolean;
  isPrivate: boolean;
  onClose: () => void;
}

export const CiUploadCommandModal: React.FC<CiUploadCommandModalProps> = ({
  appName,
  isTuf,
  isPrivate,
  onClose,
}) => {
  const [channel, setChannel] = useState('');
  const [platform, setPlatform] = useState('');
  const [arch, setArch] = useState('');
  const [updater, setUpdater] = useState('');
  const [publish, setPublish] = useState(false);
  const [critical, setCritical] = useState(false);

  const { channels } = useChannelQuery();
  const { platforms } = usePlatformQuery();
  const { architectures } = useArchitectureQuery();
  const { toastSuccess, toastError } = useToast();

  const allowedUpdaters = (platformName: string): Updater[] => {
    const updaters = platforms.find(p => p.PlatformName === platformName)?.Updaters || [];
    return isPrivate ? updaters.filter(u => !PRIVATE_BLOCKED_UPDATERS.includes(u.type)) : updaters;
  };

  const platformUpdaters = platforms.find(p => p.PlatformName === platform)?.Updaters || [];
  const availableUpdaters = allowedUpdaters(platform);
  const noAllowedUpdater = platformUpdaters.length > 0 && availableUpdaters.length === 0;

  const handlePlatformChange = (value: string) => {
    setPlatform(value);
    const updaters = allowedUpdaters(value);
    setUpdater(updaters.find(u => u.default)?.type || '');
  };

  const missing = [
    channels.length > 0 && !channel && 'channel',
    platforms.length > 0 && !platform && 'platform',
    architectures.length > 0 && !arch && 'architecture',
    availableUpdaters.length > 0 && !updater && 'updater',
  ].filter((item): item is string => Boolean(item));

  const script =
    missing.length > 0 || noAllowedUpdater
      ? ''
      : generatePresignedUploadScript({
          apiURL: env.API_URL || '',
          appName,
          channel,
          platform,
          arch,
          updater,
          publish,
          critical,
          tuf: isTuf,
        });

  const handleCopy = async () => {
    if (await copyToClipboard(script)) {
      toastSuccess('Script copied to clipboard');
    } else {
      toastError('Failed to copy script');
    }
  };

  return (
    <BaseModal
      title="CI upload command"
      onClose={onClose}
      className="w-[760px] max-w-[95vw] max-h-[85vh] overflow-y-auto"
    >
      <p className={`${HINT} mb-4`}>
        A bash script that uploads a build of <span className="font-semibold text-white/85">{appName}</span> with
        presigned URLs: files go straight to object storage, so large CI uploads skip the reverse proxy. Needs only
        curl, jq and openssl. The values below become the script's defaults; override any of them per run with
        flags (<code>--channel</code>, <code>--platform</code>, <code>--arch</code>, ...). Version and files are passed
        as arguments, the token via <code>FAYNOSYNC_TOKEN</code>. Usage is in the script header.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        {channels.length > 0 && (
          <div>
            <label className={FIELD_LABEL}>Channel</label>
            <Dropdown
              ariaLabel="Channel"
              placeholder="Select a channel"
              value={channel}
              onChange={setChannel}
              options={channels.map(c => ({ value: c.ChannelName, label: c.ChannelName }))}
            />
          </div>
        )}

        {platforms.length > 0 && (
          <div>
            <label className={FIELD_LABEL}>Platform</label>
            <Dropdown
              ariaLabel="Platform"
              placeholder="Select a platform"
              value={platform}
              onChange={handlePlatformChange}
              options={platforms.map(p => ({
                value: p.PlatformName,
                label: p.PlatformName,
                icon: getPlatformIcon(p.PlatformName),
              }))}
            />
          </div>
        )}

        {architectures.length > 0 && (
          <div>
            <label className={FIELD_LABEL}>Architecture</label>
            <Dropdown
              ariaLabel="Architecture"
              placeholder="Select an architecture"
              value={arch}
              onChange={setArch}
              options={architectures.map(a => ({ value: a.ArchID, label: a.ArchID }))}
            />
          </div>
        )}

        {availableUpdaters.length > 0 && (
          <div>
            <label className={FIELD_LABEL}>Updater</label>
            <Dropdown
              ariaLabel="Updater"
              placeholder="Select an updater"
              value={updater}
              onChange={setUpdater}
              options={availableUpdaters.map(u => ({
                value: u.type,
                label: u.default ? `${u.type} (default)` : u.type,
              }))}
            />
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-2">
        <FlagCheckbox label="Publish" tone="green" checked={publish} onChange={setPublish} />
        <FlagCheckbox label="Critical" tone="red" checked={critical} onChange={setCritical} />
      </div>
      <p className={`${HINT} mb-2`}>
        One run uploads one platform/architecture. For a multi-platform release run it per platform with the same
        version and channel. Publish, critical and changelog come only from the upload that creates the version, so
        keep Publish off and publish later from the dashboard.
      </p>
      <p className={`${HINT} mb-4`}>
        {isTuf
          ? 'TUF is enabled: the manifest includes sha256 and sha512, which TUF signs. An artifact without them cannot be signed.'
          : 'TUF is disabled: the manifest has name and md5 only. sha256/sha512 are used only for TUF signing.'}
        {isPrivate && ' Private app: velopack, sparkle, electron-builder and squirrel_windows are not available.'}
      </p>

      {noAllowedUpdater ? (
        <div className={`${NOTE_WARNING} mb-4`}>
          <i className="fas fa-exclamation-triangle"></i>
          <span>Every updater of this platform is unavailable for private apps, so the upload would be rejected.</span>
        </div>
      ) : missing.length > 0 ? (
        <div className="mb-4 rounded-lg border border-dashed border-white/25 px-4 py-6 text-center text-sm text-white/70">
          Select {missing.join(', ')} to generate the script.
        </div>
      ) : (
        <div className="relative mb-2">
          <pre className="bg-theme-input rounded-lg p-3 pr-24 font-mono text-xs text-theme-primary overflow-x-auto whitespace-pre max-h-[45vh]">
            {script}
          </pre>
          <button
            type="button"
            onClick={handleCopy}
            className={`${BTN_PRIMARY} absolute top-2 right-2 flex items-center gap-2 px-3 py-1.5 text-xs`}
          >
            <i className="fas fa-copy"></i>
            Copy
          </button>
        </div>
      )}

      <div className="flex items-center justify-between gap-4 mt-4">
        <a
          href={PRESIGNED_UPLOADS_DOCS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-white/80 underline hover:text-theme-primary"
        >
          Presigned uploads documentation
        </a>
        <button type="button" onClick={onClose} className={BTN_GHOST}>
          Close
        </button>
      </div>
    </BaseModal>
  );
};
