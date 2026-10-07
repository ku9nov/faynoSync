import React from 'react';
import { AxiosError } from 'axios';
import { DownloadMode } from '@/hooks/use-query/useAppsQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { DownloadToken, useDownloadTokensQuery } from '@/hooks/use-query/useDownloadTokensQuery';
import { useToast } from '@/hooks/useToast';
import { DownloadTokenModal } from '@/components/modals/DownloadTokenModal';
import { BTN_GHOST, ROW, ROW_META, ROW_TITLE, SECTION_LABEL } from '@/components/common/ui';

interface DownloadTokensSectionProps {
  appId: string;
  downloadMode?: DownloadMode;
  formatDate: (dateString: string) => string;
}

type TokenRow = {
  channelId: string;
  channelName: string;
  token?: DownloadToken;
};

const NO_CHANNEL_LABEL = 'No channel';

export const DownloadTokensSection: React.FC<DownloadTokensSectionProps> = ({ appId, downloadMode, formatDate }) => {
  const { channels, isLoading: isChannelsLoading } = useChannelQuery();
  const isUnlisted = downloadMode === 'unlisted';
  const { downloadTokens, isLoading: isTokensLoading, isError, regenerateDownloadToken } = useDownloadTokensQuery(!!appId && !isUnlisted);
  const { toastError } = useToast();
  const [pendingChannelId, setPendingChannelId] = React.useState<string | null>(null);
  const [revealed, setRevealed] = React.useState<{ token: string; channelName: string; replacedExisting: boolean } | null>(null);

  const rows = React.useMemo<TokenRow[]>(() => {
    const appTokens = downloadTokens.filter((token) => token.app_id === appId);
    const byChannel = new Map(appTokens.map((token) => [token.channel_id || '', token]));
    const knownChannelIds = new Set(channels.map((channel) => channel.ID));

    const result: TokenRow[] = channels.map((channel) => ({
      channelId: channel.ID,
      channelName: channel.ChannelName,
      token: byChannel.get(channel.ID),
    }));

    appTokens
      .filter((token) => token.channel_id && !knownChannelIds.has(token.channel_id))
      .forEach((token) => result.push({ channelId: token.channel_id, channelName: token.channel_name, token }));

    if (channels.length === 0 || byChannel.has('')) {
      result.push({ channelId: '', channelName: NO_CHANNEL_LABEL, token: byChannel.get('') });
    }

    return result;
  }, [downloadTokens, channels, appId]);

  const handleRegenerate = async (row: TokenRow) => {
    if (pendingChannelId !== null) {
      return;
    }

    if (row.token) {
      const confirmed = window.confirm(
        `Regenerate the download token for "${row.channelName}"? The current token will stop working immediately and clients using it will no longer be able to download.`
      );
      if (!confirmed) {
        return;
      }
    }

    setPendingChannelId(row.channelId);
    try {
      const result = await regenerateDownloadToken(appId, row.channelId || undefined);
      setRevealed({ token: result.token, channelName: row.channelName, replacedExisting: !!row.token });
    } catch (err) {
      const axiosError = err as AxiosError<{ error?: string; message?: string }>;
      toastError(
        axiosError.response?.data?.error ||
          axiosError.response?.data?.message ||
          axiosError.message ||
          'Failed to generate download token'
      );
    } finally {
      setPendingChannelId(null);
    }
  };

  const isLoading = isChannelsLoading || isTokensLoading;

  return (
    <div className="mb-6">
      <div className={`${SECTION_LABEL} mb-2`}>Download tokens</div>
      <p className="mb-3 text-xs text-white/60">
        {isUnlisted
          ? 'This app is unlisted: anyone with the /download link can download, so tokens are not required. Tokens are only enforced for strict apps.'
          : 'Tokens are only enforced for strict apps. One token per channel.'}{' '}
        Clients send the token in the <span className="font-mono text-white/80">X-Download-Token</span> header.
      </p>

      {isUnlisted ? null : isLoading ? (
        <p className="text-xs text-white/70">Loading...</p>
      ) : isError ? (
        <p className="text-xs text-red-300">Failed to load download tokens</p>
      ) : (
        <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
          {rows.map((row) => {
            const isPending = pendingChannelId === row.channelId;
            return (
              <div key={row.channelId || NO_CHANNEL_LABEL} className={ROW}>
                <div className="min-w-0">
                  <p className={ROW_TITLE}>{row.channelName}</p>
                  <div className={ROW_META}>
                    {row.token ? (
                      <>
                        <span>{row.token.token_prefix}…</span>
                        <span aria-hidden="true">·</span>
                        <span>Updated {formatDate(row.token.updated_at)}</span>
                      </>
                    ) : (
                      <span>No token</span>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleRegenerate(row)}
                  disabled={pendingChannelId !== null}
                  className={`${BTN_GHOST} flex shrink-0 items-center gap-2 px-3 py-1.5 text-xs ${
                    row.token ? 'border-red-400/40 text-red-300 hover:bg-red-500/20' : ''
                  }`}
                >
                  <i className={`fas ${row.token ? 'fa-sync-alt' : 'fa-key'} ${isPending ? 'animate-spin' : ''}`}></i>
                  {isPending ? 'Working...' : row.token ? 'Regenerate' : 'Generate'}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {revealed && (
        <DownloadTokenModal
          token={revealed.token}
          channelName={revealed.channelName}
          replacedExisting={revealed.replacedExisting}
          onClose={() => setRevealed(null)}
        />
      )}
    </div>
  );
};
