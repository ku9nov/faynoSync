import React from 'react';
import { AppListItem } from '@/hooks/use-query/useAppsQuery';
import { Dropdown } from '@/components/common/Dropdown';
import { FIELD_LABEL } from '@/components/common/ui';

interface AppSelectionProps {
  apps: AppListItem[];
  selectedApp: string;
  onAppChange: (appName: string) => void;
  onResetStates: () => void;
}

export const AppSelection: React.FC<AppSelectionProps> = ({
  apps,
  selectedApp,
  onAppChange,
  onResetStates,
}) => {

  // Filter apps with Tuf: true
  const tufApps = React.useMemo(() => {
    if (!Array.isArray(apps)) return [];
    return apps.filter(app => app.Tuf === true);
  }, [apps]);

  const handleAppSelect = (appName: string) => {
    onAppChange(appName);
    onResetStates();
  };

  return (
    <div className="rounded-lg border border-white/15 bg-violet-950/30 p-4">
      <label className={FIELD_LABEL}>Select app</label>
      <Dropdown
        ariaLabel="App"
        placeholder="Select an app with TUF enabled"
        emptyMessage="No apps with TUF enabled found"
        value={selectedApp}
        onChange={handleAppSelect}
        options={tufApps.map((app) => ({ value: app.AppName, label: app.AppName }))}
      />
      {tufApps.length > 0 && (
        <p className="mt-2 text-xs text-white/60">
          <i className="fas fa-info-circle mr-1"></i>
          Only apps with TUF enabled are shown
        </p>
      )}
    </div>
  );
};
