import React, { useEffect, useMemo, useState } from 'react';
import axiosInstance from '@/config/axios';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useToast } from '@/hooks/useToast';
import { AllowedItemsModal } from '@/components/settings/AllowedItemsModal';
import { Dropdown } from '@/components/common/Dropdown';

type ExpirationValue = '1d' | '7d' | '30d' | '90d' | 'never';

interface TokenListItem {
  id: string;
  name: string;
  token_prefix: string;
  allowed_apps: string[];
  expires_at?: string | null;
  created_at: string;
  last_used_at?: string | null;
}

interface CreateTokenResult extends TokenListItem {
  token: string;
}

interface TokenListResponse {
  tokens: TokenListItem[];
}

interface ErrorResponse {
  error?: string;
  message?: string;
}

const expirationOptions: { value: ExpirationValue; label: string }[] = [
  { value: '1d', label: '1 day' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: 'never', label: 'Never' },
];

const expirationDays: Record<Exclude<ExpirationValue, 'never'>, number> = {
  '1d': 1,
  '7d': 7,
  '30d': 30,
  '90d': 90,
};

const getErrorMessage = (error: unknown, fallbackMessage: string): string => {
  if (typeof error === 'object' && error !== null) {
    const maybeError = error as {
      response?: { data?: ErrorResponse };
      message?: string;
    };

    if (maybeError.response?.data?.error) {
      return maybeError.response.data.error;
    }

    if (maybeError.response?.data?.message) {
      return maybeError.response.data.message;
    }

    if (maybeError.message) {
      return maybeError.message;
    }
  }

  return fallbackMessage;
};

const formatDate = (value?: string | null): string => {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
};

const calculateExpiresAt = (expiration: ExpirationValue): string | undefined => {
  if (expiration === 'never') return undefined;

  const daysToAdd = expirationDays[expiration];
  const expiresAt = new Date();
  expiresAt.setUTCDate(expiresAt.getUTCDate() + daysToAdd);

  return expiresAt.toISOString();
};

export const TokenSettings: React.FC = () => {
  const { apps } = useAppsQuery();
  const { toastSuccess, toastError } = useToast();

  const [tokens, setTokens] = useState<TokenListItem[]>([]);
  const [isLoadingTokens, setIsLoadingTokens] = useState(true);
  const [isCreatingToken, setIsCreatingToken] = useState(false);
  const [isRevokingById, setIsRevokingById] = useState<Record<string, boolean>>({});
  const [isAllowedAppsModalOpen, setIsAllowedAppsModalOpen] = useState(false);

  const [name, setName] = useState('');
  const [selectedAppIds, setSelectedAppIds] = useState<string[]>([]);
  const [expiration, setExpiration] = useState<ExpirationValue>('30d');
  const [lastCreatedToken, setLastCreatedToken] = useState<CreateTokenResult | null>(null);

  const appItems = useMemo(() => {
    if (!Array.isArray(apps)) {
      return [];
    }

    return apps
      .map((app) => ({ id: app.ID, name: app.AppName }))
      .filter((app) => app.id && app.name);
  }, [apps]);

  const appNameById = useMemo(() => {
    return new Map(appItems.map((app) => [app.id, app.name]));
  }, [appItems]);

  const selectedAppsPreview = useMemo(() => {
    return selectedAppIds.map((id) => appNameById.get(id) || id);
  }, [selectedAppIds, appNameById]);

  const loadTokens = async (showLoader = true) => {
    if (showLoader) {
      setIsLoadingTokens(true);
    }

    try {
      const response = await axiosInstance.get<TokenListResponse | ErrorResponse>('/token/list');
      const data = response.data;

      if ('error' in data && data.error) {
        toastError(data.error);
        setTokens([]);
        return;
      }

      if (!('tokens' in data)) {
        setTokens([]);
        return;
      }

      const tokenItems: TokenListItem[] = Array.isArray(data.tokens) ? data.tokens : [];
      const sortedTokens = tokenItems.slice().sort((a: TokenListItem, b: TokenListItem) => {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      });

      setTokens(sortedTokens);
    } catch (error) {
      toastError(getErrorMessage(error, 'Failed to load tokens'));
    } finally {
      setIsLoadingTokens(false);
    }
  };

  useEffect(() => {
    loadTokens();
  }, []);

  const handleCreateToken = async () => {
    const trimmedName = name.trim();
    if (!trimmedName) {
      toastError('Token name is required');
      return;
    }

    if (selectedAppIds.length === 0) {
      toastError('Please select at least one allowed app');
      return;
    }

    const expiresAt = calculateExpiresAt(expiration);
    const payload: {
      name: string;
      allowed_apps: string[];
      expires_at?: string;
    } = {
      name: trimmedName,
      allowed_apps: selectedAppIds,
    };

    if (expiresAt) {
      payload.expires_at = expiresAt;
    }

    setIsCreatingToken(true);

    try {
      const response = await axiosInstance.post<CreateTokenResult | ErrorResponse>('/token/create', payload);
      const data = response.data;

      if ('error' in data && data.error) {
        toastError(data.error);
        return;
      }

      if (!('token' in data)) {
        toastError('Token was created, but response is invalid');
        return;
      }

      setLastCreatedToken(data);
      toastSuccess('Token created successfully');
      setName('');
      setSelectedAppIds([]);
      setExpiration('30d');
      await loadTokens(false);
    } catch (error) {
      toastError(getErrorMessage(error, 'Failed to create token'));
    } finally {
      setIsCreatingToken(false);
    }
  };

  const handleRevokeToken = async (id: string) => {
    setIsRevokingById((prev) => ({ ...prev, [id]: true }));

    try {
      const response = await axiosInstance.delete<ErrorResponse>('/token/delete', {
        data: { id },
      });

      if (response.data.error) {
        toastError(response.data.error);
        return;
      }

      toastSuccess(response.data.message || 'Token revoked');
      await loadTokens(false);
    } catch (error) {
      toastError(getErrorMessage(error, 'Failed to revoke token'));
    } finally {
      setIsRevokingById((prev) => ({ ...prev, [id]: false }));
    }
  };

  const handleCopyLastToken = async () => {
    if (!lastCreatedToken?.token) return;

    try {
      await navigator.clipboard.writeText(lastCreatedToken.token);
      toastSuccess('Token copied to clipboard');
    } catch (_error) {
      toastError('Failed to copy token');
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg p-4 border border-theme-card-hover">
        <h2 className="text-lg font-semibold text-theme-primary mb-4">Create CI/CD Token</h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm text-theme-primary mb-2">Token name</label>
            <input
              type="text"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="GitHub Actions - MyApp"
              className="w-full rounded-lg border border-theme-modal bg-theme-input text-theme-primary px-3 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
          </div>

          <div>
            <label className="block text-sm text-theme-primary mb-2">Expiration</label>
            <Dropdown
              ariaLabel="Expiration"
              value={expiration}
              onChange={(value) => setExpiration(value as ExpirationValue)}
              options={expirationOptions.map((option) => ({ value: option.value, label: option.label }))}
            />
          </div>
        </div>

        <div className="mt-4 flex flex-col sm:flex-row sm:items-center gap-3">
          <button
            onClick={() => setIsAllowedAppsModalOpen(true)}
            className="bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors duration-200"
          >
            <i className="fas fa-search mr-2"></i>
            Select allowed apps ({selectedAppIds.length})
          </button>

          <button
            onClick={handleCreateToken}
            disabled={isCreatingToken}
            className={`bg-theme-button-primary text-theme-primary px-4 py-2 rounded-lg transition-colors duration-200 ${
              isCreatingToken ? 'opacity-60 cursor-not-allowed' : 'hover:bg-theme-button-primary-hover'
            }`}
          >
            {isCreatingToken ? (
              <>
                <i className="fas fa-spinner fa-spin mr-2"></i>
                Creating...
              </>
            ) : (
              <>
                <i className="fas fa-key mr-2"></i>
                Create token
              </>
            )}
          </button>
        </div>

        {selectedAppsPreview.length > 0 && (
          <div className="mt-3 text-sm text-theme-primary opacity-80">
            {selectedAppsPreview.join(', ')}
          </div>
        )}
      </div>

      {lastCreatedToken && (
        <div className="rounded-lg p-4 border border-theme-card-hover">
          <div className="flex flex-col gap-2">
            <h3 className="text-md font-semibold text-theme-primary">New token (shown once)</h3>
            <div className="break-all text-sm text-theme-primary bg-theme-input rounded-lg p-3 border border-theme-modal">
              {lastCreatedToken.token}
            </div>
            <div className="flex">
              <button
                onClick={handleCopyLastToken}
                className="bg-theme-button-primary text-theme-primary px-3 py-2 rounded-lg hover:bg-theme-button-primary-hover transition-colors duration-200"
              >
                <i className="fas fa-copy mr-2"></i>
                Copy token
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="rounded-lg p-4 border border-theme-card-hover">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-theme-primary">Issued tokens</h2>
          <button
            onClick={() => loadTokens()}
            className="text-theme-primary hover:text-theme-button-primary"
            title="Refresh tokens list"
          >
            <i className="fas fa-sync-alt mr-2"></i>
            Refresh
          </button>
        </div>

        {isLoadingTokens ? (
          <div className="text-theme-primary">Loading tokens...</div>
        ) : tokens.length === 0 ? (
          <div className="text-theme-primary opacity-80">No tokens found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left border-b border-theme-modal">
                  <th className="py-2 pr-3 text-theme-primary">Name</th>
                  <th className="py-2 pr-3 text-theme-primary">Prefix</th>
                  <th className="py-2 pr-3 text-theme-primary">Allowed apps</th>
                  <th className="py-2 pr-3 text-theme-primary">Expires</th>
                  <th className="py-2 pr-3 text-theme-primary">Created</th>
                  <th className="py-2 pr-3 text-theme-primary">Last used</th>
                  <th className="py-2 text-theme-primary">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="border-b border-theme-modal last:border-b-0">
                    <td className="py-2 pr-3 text-theme-primary">{token.name}</td>
                    <td className="py-2 pr-3 text-theme-primary">{token.token_prefix}</td>
                    <td className="py-2 pr-3 text-theme-primary">
                      {token.allowed_apps.length === 0
                        ? '-'
                        : token.allowed_apps.map((id) => appNameById.get(id) || id).join(', ')}
                    </td>
                    <td className="py-2 pr-3 text-theme-primary">{formatDate(token.expires_at)}</td>
                    <td className="py-2 pr-3 text-theme-primary">{formatDate(token.created_at)}</td>
                    <td className="py-2 pr-3 text-theme-primary">{formatDate(token.last_used_at)}</td>
                    <td className="py-2">
                      <button
                        onClick={() => handleRevokeToken(token.id)}
                        disabled={isRevokingById[token.id]}
                        className={`text-theme-primary hover:opacity-80 ${isRevokingById[token.id] ? 'opacity-60 cursor-not-allowed' : ''}`}
                        title="Revoke token"
                      >
                        {isRevokingById[token.id] ? (
                          <i className="fas fa-spinner fa-spin"></i>
                        ) : (
                          <i className="fas fa-trash-alt"></i>
                        )}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <AllowedItemsModal
        isOpen={isAllowedAppsModalOpen}
        onClose={() => setIsAllowedAppsModalOpen(false)}
        title="Allowed Apps"
        items={appItems}
        selectedIds={selectedAppIds}
        onSave={setSelectedAppIds}
      />
    </div>
  );
};
