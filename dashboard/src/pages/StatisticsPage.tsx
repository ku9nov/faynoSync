import React, { useState } from 'react';
import { useTelemetryQuery } from '@/hooks/use-query/useTelemetryQuery';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend, Area, AreaChart } from 'recharts';
import { useAppsQuery } from '@/hooks/use-query/useAppsQuery';
import { useRolloutVersions, useRolloutAdoption } from '@/hooks/use-query/useRolloutQuery';
import { useChannelQuery } from '@/hooks/use-query/useChannelQuery';
import { usePlatformQuery } from '@/hooks/use-query/usePlatformQuery';
import { useArchitectureQuery } from '@/hooks/use-query/useArchitectureQuery';
import { useTheme } from '@/providers/themeProvider';
import { AppListItem } from '@/hooks/use-query/useAppsQuery';
import { Channel } from '@/hooks/use-query/useChannelQuery';
import { Platform } from '@/hooks/use-query/usePlatformQuery';
import { Architecture } from '@/hooks/use-query/useArchitectureQuery';
import DatePicker from 'react-datepicker';
import "react-datepicker/dist/react-datepicker.css";
import { Dropdown } from '@/components/common/Dropdown';
import { FIELD_LABEL, STATUS_BADGE } from '@/components/common/ui';
import { getPlatformIcon } from '@/utils/platformIcon';

const PANEL_CLASS = 'bg-theme-card rounded-lg border border-theme-card-hover shadow-md backdrop-blur-lg';
const CHART_GRID_STROKE = 'rgba(148, 163, 184, 0.25)';
const CHART_AXIS_STROKE = 'rgba(148, 163, 184, 0.7)';
const TOOLTIP_STYLE = {
  backgroundColor: 'var(--theme-card)',
  border: '1px solid var(--theme-card-hover)',
  color: 'var(--theme-primary)',
  borderRadius: '12px',
  boxShadow: '0 10px 30px rgba(15, 23, 42, 0.25)',
};
const DATE_PICKER_POPUP_STYLE = {
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  boxShadow: '0 16px 40px rgba(15, 23, 42, 0.35)',
};

const DARK_CHART_COLORS = ['#5AA9FF', '#34D399', '#F59E0B', '#F97316', '#A78BFA', '#2DD4BF', '#FB7185', '#22D3EE'];
const LIGHT_CHART_COLORS = ['#2563EB', '#059669', '#D97706', '#EA580C', '#7C3AED', '#0D9488', '#E11D48', '#0891B2'];

type Filters = {
  apps: string[];
  channels: string[];
  platforms: string[];
  architectures: string[];
  range?: 'today' | 'week' | 'month';
  date?: string;
};

const StatCard = ({ title, value, icon }: { title: string; value: number; icon: React.ReactNode }) => (
  <div className={`${PANEL_CLASS} relative overflow-hidden p-5 sm:p-6 transition-all duration-200 hover:-translate-y-1 hover:shadow-xl`}>
    <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-r from-white/10 via-transparent to-transparent" />
    <div className="relative flex items-center justify-between gap-3">
      <div>
        <p className="text-theme-secondary text-xs uppercase tracking-[0.08em]">{title}</p>
        <p className="text-2xl sm:text-3xl font-semibold mt-2 text-theme-primary tabular-nums">{value}</p>
      </div>
      <div className="h-10 w-10 sm:h-11 sm:w-11 rounded-xl bg-white/10 border border-white/20 flex items-center justify-center text-theme-primary shrink-0">
        {icon}
      </div>
    </div>
  </div>
);

const RolloutHealthRow = ({
  appName,
  version,
  channel,
  configuredPercent,
  observedPercent,
  observedClients,
  eligibleClients,
  barColor,
}: {
  appName: string;
  version: string;
  channel: string;
  configuredPercent: number;
  observedPercent: number | null;
  observedClients: number | null;
  eligibleClients: number | null;
  barColor: string;
}) => {
  const clampedObserved = observedPercent === null ? 0 : Math.min(Math.max(observedPercent, 0), 100);
  const clampedTarget = Math.min(Math.max(configuredPercent, 0), 100);
  return (
    <div className={`${PANEL_CLASS} p-4`}>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-theme-primary font-semibold truncate">{appName}</span>
          <span className="text-theme-secondary text-sm">v{version}</span>
          <span className="text-theme-secondary text-xs px-2 py-0.5 rounded-full bg-white/10 border border-white/20">{channel}</span>
        </div>
        <div className="flex items-center gap-4 text-sm tabular-nums">
          <span className="text-theme-secondary">
            target <span className="text-theme-primary font-semibold">{configuredPercent}%</span>
          </span>
          <span className="text-theme-secondary">
            observed{' '}
            <span className="text-theme-primary font-semibold">
              {observedPercent === null ? '—' : `${observedPercent.toFixed(1)}%`}
            </span>
          </span>
        </div>
      </div>
      <div className="relative h-3 rounded-full bg-white/10 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${clampedObserved}%`, background: barColor }}
        />
      </div>
      <div className="relative h-0">
        <div
          className="absolute -top-3 h-3 w-0.5 bg-theme-primary"
          style={{ left: `${clampedTarget}%` }}
          title={`Target ${configuredPercent}%`}
        />
      </div>
      <p className="text-theme-secondary text-xs mt-3">
        {observedClients === null || eligibleClients === null
          ? 'No telemetry for this version in the selected period.'
          : `${formatNumber(observedClients)} of ${formatNumber(eligibleClients)} eligible clients on this version or newer.`}
      </p>
    </div>
  );
};

const numberFormatter = new Intl.NumberFormat('en-US');

const formatNumber = (value: number | string) => {
  const normalizedValue = typeof value === 'number' ? value : Number(value);
  if (Number.isNaN(normalizedValue)) {
    return String(value);
  }
  return numberFormatter.format(normalizedValue);
};

const formatChartDate = (value: string) => {
  const parsedDate = new Date(value);
  if (Number.isNaN(parsedDate.getTime())) {
    return value;
  }
  return parsedDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
};

const formatChartDateLong = (value: string) => {
  const parsedDate = new Date(value);
  if (Number.isNaN(parsedDate.getTime())) {
    return value;
  }
  return parsedDate.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
};

const compareVersions = (a: string, b: string) => {
  const partsA = a.replace(/^v/i, '').split('.').map(Number);
  const partsB = b.replace(/^v/i, '').split('.').map(Number);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const numA = partsA[i] ?? 0;
    const numB = partsB[i] ?? 0;
    if (Number.isNaN(numA) || Number.isNaN(numB)) {
      const cmp = a.localeCompare(b);
      if (cmp !== 0) {
        return cmp;
      }
      continue;
    }
    if (numA !== numB) {
      return numA - numB;
    }
  }
  return 0;
};

const SinglePointTrendView = ({
  value,
  color,
  dateLabel,
}: {
  value: number;
  color: string;
  dateLabel: string;
}) => (
  <div className="h-full w-full flex items-center justify-center">
    <div className="text-center">
      <p className="text-theme-secondary text-xs sm:text-sm uppercase tracking-[0.08em]">Single Day Snapshot</p>
      <p className="mt-3 text-4xl sm:text-5xl font-semibold tabular-nums" style={{ color }}>
        {formatNumber(value)}
      </p>
      <p className="mt-3 text-theme-secondary text-sm">{dateLabel}</p>
    </div>
  </div>
);

const MultiFilter = ({
  label,
  placeholder,
  values,
  options,
  onToggle,
  panelClassName,
}: {
  label: string;
  placeholder: string;
  values: string[];
  options: { value: string; label: string; icon?: string }[];
  onToggle: (value: string) => void;
  panelClassName: string;
}) => (
  <div className={panelClassName}>
    <label className={FIELD_LABEL}>{label}</label>
    <Dropdown
      multiple
      ariaLabel={label}
      placeholder={placeholder}
      value={values}
      onChange={onToggle}
      options={options}
    />
    {values.length > 0 && (
      <div className="mt-2 flex flex-wrap gap-2">
        {values.map((value) => (
          <span key={value} className={`${STATUS_BADGE} border-white/15 text-white/85`}>
            {value}
            <button
              type="button"
              onClick={() => onToggle(value)}
              className="ml-1 rounded p-0.5 text-white/70 transition-colors hover:bg-white/15 hover:text-red-300"
              aria-label={`Remove ${value}`}
            >
              <i className="fas fa-times"></i>
            </button>
          </span>
        ))}
      </div>
    )}
  </div>
);

export const StatisticsPage = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { theme } = useTheme();
  const [filters, setFilters] = useState<Filters>({
    apps: [],
    channels: [],
    platforms: [],
    architectures: [],
    range: 'today'
  });
  const [selectedDate, setSelectedDate] = useState<Date | null>(null);
  const [showDatePicker, setShowDatePicker] = useState(false);

  const tooltipTextColor = theme === 'dark' ? '#FFFFFF' : '#000000';
  const tooltipContentStyle = React.useMemo(
    () => ({ ...TOOLTIP_STYLE, color: tooltipTextColor }),
    [tooltipTextColor]
  );
  const tooltipLabelStyle = React.useMemo(
    () => ({
      color: tooltipTextColor,
      fontWeight: 'bold',
      marginBottom: '4px',
    }),
    [tooltipTextColor]
  );
  const tooltipItemStyle = React.useMemo(
    () => ({
      color: tooltipTextColor,
      padding: '4px 0',
    }),
    [tooltipTextColor]
  );
  const chartColors = React.useMemo(
    () => (theme === 'dark' ? DARK_CHART_COLORS : LIGHT_CHART_COLORS),
    [theme]
  );
  const lineChartConfig = React.useMemo(
    () => ({
      requests: chartColors[0],
      uniqueClients: chartColors[1],
      latestUsers: chartColors[2],
      outdatedClients: chartColors[3],
    }),
    [chartColors]
  );

  const sharedTooltipProps = React.useMemo(
    () => ({
      contentStyle: tooltipContentStyle,
      labelStyle: tooltipLabelStyle,
      itemStyle: tooltipItemStyle,
      formatter: (value: number | string) => formatNumber(value),
    }),
    [tooltipContentStyle, tooltipLabelStyle, tooltipItemStyle]
  );
  const { apps = [] } = useAppsQuery();
  const { channels = [] } = useChannelQuery();
  const { platforms = [] } = usePlatformQuery();
  const { architectures = [] } = useArchitectureQuery();
  const { data, isLoading, refetch } = useTelemetryQuery(filters);
  const rolloutAppNames = React.useMemo(
    () => (filters.apps.length ? filters.apps : (apps as AppListItem[]).map((a) => a.AppName)),
    [filters.apps, apps]
  );
  const rolloutScope = React.useMemo(
    () => ({ channels: filters.channels, platforms: filters.platforms, architectures: filters.architectures }),
    [filters.channels, filters.platforms, filters.architectures]
  );
  const { rolloutVersions } = useRolloutVersions(rolloutAppNames, rolloutScope);
  const rolloutAppList = React.useMemo(
    () => [...new Set(rolloutVersions.map((r) => r.appName))],
    [rolloutVersions]
  );
  const adoptionFilters = React.useMemo(
    () => ({
      channels: filters.channels,
      platforms: filters.platforms,
      architectures: filters.architectures,
      range: filters.range,
      date: filters.date,
    }),
    [filters.channels, filters.platforms, filters.architectures, filters.range, filters.date]
  );
  const { byApp: adoptionByApp } = useRolloutAdoption(rolloutAppList, adoptionFilters);
  const rolloutRows = React.useMemo(() => {
    return rolloutVersions
      .map((r) => {
        const app = adoptionByApp[r.appName];
        // Hide rollouts for apps with no telemetry in view (idle/other apps),
        // but keep apps that have traffic even if this version is at 0% adoption.
        if (!app || app.uniqueClients <= 0) {
          return null;
        }
        const usageList = app.usage;
        const hasUsage = usageList.some((u) => u.version === r.version);
        const geCount = (version: string) =>
          usageList.reduce(
            (acc, u) => acc + (compareVersions(u.version, version) >= 0 ? u.client_count : 0),
            0
          );
        const predecessor = [...usageList]
          .map((u) => u.version)
          .sort(compareVersions)
          .reverse()
          .find((v) => compareVersions(v, r.version) < 0);
        const observedClients = hasUsage ? geCount(r.version) : null;
        const eligibleClients = predecessor ? geCount(predecessor) : app.uniqueClients;
        const observedPercent =
          hasUsage && eligibleClients > 0 ? ((observedClients as number) / eligibleClients) * 100 : null;
        return { r, observedClients, eligibleClients, observedPercent };
      })
      .filter((row): row is NonNullable<typeof row> => row !== null);
  }, [rolloutVersions, adoptionByApp]);
  const dailyStats = React.useMemo(() => (Array.isArray(data?.daily_stats) ? data.daily_stats : []), [data?.daily_stats]);
  const hasTrendData = dailyStats.length > 0;
  const showSinglePointTrend = dailyStats.length === 1;
  const singlePointDateLabel = showSinglePointTrend ? formatChartDateLong(String(dailyStats[0].date)) : '';

  const handleOptionClick = (dropdownName: keyof Filters, value: string) => {
    setFilters(prev => {
      const currentValues = prev[dropdownName] as string[];
      const newValues = currentValues.includes(value)
        ? currentValues.filter(v => v !== value)
        : [...currentValues, value];
      return { ...prev, [dropdownName]: newValues };
    });
  };

  const handleTimeRangeChange = (range: 'today' | 'week' | 'month' | 'custom') => {
    if (range === 'custom') {
      setShowDatePicker(true);
      setFilters(prev => ({ ...prev, range: undefined, date: undefined }));
    } else {
      setShowDatePicker(false);
      setSelectedDate(null);
      setFilters(prev => ({ ...prev, range, date: undefined }));
    }
  };

  const handleDateChange = (date: Date | null) => {
    setSelectedDate(date);
    if (date) {
      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      const formattedDate = `${year}-${month}-${day}`;
      setFilters(prev => ({ ...prev, date: formattedDate, range: undefined }));
      setShowDatePicker(false);
    }
  };

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      if (!target.closest('.react-datepicker') && !target.closest('.date-picker-container')) {
        setShowDatePicker(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-theme-gradient font-sans">
        <div className="flex">
          <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
          <main className="flex-1 min-w-0 p-8">
            <Header
              title="Statistics"
              onMenuClick={() => setIsSidebarOpen(true)}
              onCreateClick={() => {}}
              createButtonText=""
              hideSearch={true}
            />
            <div className="flex items-center justify-center h-[calc(100vh-200px)]">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-theme-primary"></div>
            </div>
          </main>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="min-h-screen bg-theme-gradient font-sans">
        <div className="flex">
          <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
          <main className="flex-1 min-w-0 p-8">
            <Header
              title="Statistics"
              onMenuClick={() => setIsSidebarOpen(true)}
              onCreateClick={() => {}}
              createButtonText=""
              hideSearch={true}
            />
            <div className="flex items-center justify-center h-[calc(100vh-200px)]">
              <div className="text-center">
                <svg className="w-16 h-16 mx-auto text-theme-primary mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <h3 className="text-xl font-semibold text-theme-primary mb-2">No Data Available</h3>
                <p className="text-theme-primary opacity-75">There are no statistics available for the selected period.</p>
              </div>
            </div>
          </main>
        </div>
      </div>
    );
  }

  const NoDataMessage = () => (
    <div className="flex items-center justify-center h-80">
      <div className="text-center">
        <svg className="w-12 h-12 mx-auto text-theme-primary mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p className="text-theme-primary opacity-75">No data available for this section</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-theme-gradient font-sans">
      <div className="flex flex-col lg:flex-row">
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
        <main className="flex-1 min-w-0 p-2 sm:p-4 md:p-8">
          <Header
            title="Statistics"
            onMenuClick={() => setIsSidebarOpen(true)}
            onCreateClick={() => {}}
            createButtonText=""
            hideSearch={true}
          />

          <div className={`${PANEL_CLASS} relative z-30 p-4 sm:p-6 mb-4 sm:mb-8`}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-theme-primary text-base sm:text-lg font-semibold">Filters & Time Range</h2>
              <span className="text-theme-secondary text-xs sm:text-sm">
                {data.summary?.total_requests || 0} requests in view
              </span>
            </div>

            {/* Time Range Selector */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between space-y-2 sm:space-y-0 sm:space-x-4">
              <button
                onClick={e => { e.currentTarget.blur(); refetch(); }}
                className={`header-action-btn flex items-center px-2 sm:px-3 py-1.5 text-base sm:text-lg font-semibold ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
                disabled={isLoading}
              >
                <svg 
                  className={`w-5 h-5 mr-2 ${isLoading ? 'animate-spin' : ''}`}
                  fill="none" 
                  stroke="currentColor" 
                  viewBox="0 0 24 24"
                >
                  <path 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    strokeWidth="2" 
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" 
                  />
                </svg>
                {isLoading ? 'Updating...' : 'Update Data'}
              </button>
              <div className="flex flex-col sm:flex-row flex-wrap items-stretch w-full sm:w-auto space-y-2 sm:space-y-0 sm:space-x-4">
                <button
                  onClick={() => handleTimeRangeChange('today')}
                  className={`header-additional-btn px-2 sm:px-4 py-2 text-sm sm:text-base ${filters.range === 'today' && !filters.date ? 'header-action-btn' : ''}`}
                >
                  Today
                </button>
                <button
                  onClick={() => handleTimeRangeChange('week')}
                  className={`header-additional-btn px-2 sm:px-4 py-2 text-sm sm:text-base ${filters.range === 'week' ? 'header-action-btn' : ''}`}
                >
                  Last Week
                </button>
                <button
                  onClick={() => handleTimeRangeChange('month')}
                  className={`header-additional-btn px-2 sm:px-4 py-2 text-sm sm:text-base ${filters.range === 'month' ? 'header-action-btn' : ''}`}
                >
                  Last Month
                </button>
                <div className="date-picker-container relative w-full sm:w-auto">
                  <button
                    onClick={() => handleTimeRangeChange('custom')}
                    className={`header-additional-btn w-full sm:w-auto px-2 sm:px-4 py-2 text-sm sm:text-base ${filters.date ? 'header-action-btn' : ''}`}
                  >
                    {filters.date ? new Date(filters.date).toLocaleDateString() : 'Custom Date'}
                  </button>
                  {showDatePicker && (
                    <div className="absolute z-[90] mt-2 right-0" style={DATE_PICKER_POPUP_STYLE}>
                      <DatePicker
                        selected={selectedDate}
                        onChange={handleDateChange}
                        inline
                        maxDate={new Date()}
                        className="bg-theme-card border border-theme-card-hover rounded-lg shadow-lg"
                        calendarClassName="react-datepicker"
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>
            {/* Filters */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mt-4">
              <MultiFilter
                label="Apps"
                placeholder="All apps"
                panelClassName={`${PANEL_CLASS} p-3 sm:p-4`}
                values={filters.apps}
                onToggle={(value) => handleOptionClick('apps', value)}
                options={(Array.isArray(apps) ? (apps as AppListItem[]) : []).map((app) => ({
                  value: app.AppName,
                  label: app.AppName,
                }))}
              />
              <MultiFilter
                label="Channels"
                placeholder="All channels"
                panelClassName={`${PANEL_CLASS} p-3 sm:p-4`}
                values={filters.channels}
                onToggle={(value) => handleOptionClick('channels', value)}
                options={(Array.isArray(channels) ? (channels as Channel[]) : []).map((channel) => ({
                  value: channel.ChannelName,
                  label: channel.ChannelName,
                }))}
              />
              <MultiFilter
                label="Platforms"
                placeholder="All platforms"
                panelClassName={`${PANEL_CLASS} p-3 sm:p-4`}
                values={filters.platforms}
                onToggle={(value) => handleOptionClick('platforms', value)}
                options={(Array.isArray(platforms) ? (platforms as Platform[]) : []).map((platform) => ({
                  value: platform.PlatformName,
                  label: platform.PlatformName,
                  icon: getPlatformIcon(platform.PlatformName),
                }))}
              />
              <MultiFilter
                label="Architectures"
                placeholder="All architectures"
                panelClassName={`${PANEL_CLASS} p-3 sm:p-4`}
                values={filters.architectures}
                onToggle={(value) => handleOptionClick('architectures', value)}
                options={(Array.isArray(architectures) ? (architectures as Architecture[]) : []).map((arch) => ({
                  value: arch.ArchID,
                  label: arch.ArchID,
                }))}
              />
            </div>
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 sm:gap-4 mb-4 sm:mb-8">
            <StatCard
              title="Total Requests"
              value={data.summary?.total_requests || 0}
              icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>}
            />
            <StatCard
              title="Unique Clients"
              value={data.summary?.unique_clients || 0}
              icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>}
            />
            <StatCard
              title="Latest Version Users"
              value={data.summary?.clients_using_latest_version || 0}
              icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>}
            />
            <StatCard
              title="Outdated Clients"
              value={data.summary?.clients_outdated || 0}
              icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>}
            />
            <StatCard
              title="Active Apps"
              value={data.summary?.total_active_apps || 0}
              icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>}
            />
          </div>

          {/* Rollout Health */}
          {rolloutRows.length > 0 && (
            <div className={`${PANEL_CLASS} p-3 sm:p-6 mb-4 sm:mb-8`}>
              <div className="flex items-center justify-between mb-2 sm:mb-4">
                <h3 className="text-base sm:text-lg font-semibold text-theme-primary">Rollout Health</h3>
                <span className="text-theme-secondary text-xs sm:text-sm">
                  {rolloutRows.length} staged {rolloutRows.length === 1 ? 'rollout' : 'rollouts'}
                </span>
              </div>
              <div className="grid grid-cols-1 gap-3">
                {rolloutRows.map(({ r, observedClients, eligibleClients, observedPercent }, index) => (
                  <RolloutHealthRow
                    key={`${r.appName}|${r.channel}|${r.version}`}
                    appName={r.appName}
                    version={r.version}
                    channel={r.channel}
                    configuredPercent={r.configuredPercent}
                    observedPercent={observedPercent}
                    observedClients={observedClients}
                    eligibleClients={eligibleClients}
                    barColor={chartColors[index % chartColors.length]}
                  />
                ))}
              </div>
              <p className="text-theme-secondary text-xs mt-4">
                Observed is adoption within the eligible pool: clients on the rollout version or newer, over clients on
                the previous version or newer — the same base the rollout percent is defined against, so it lines up with
                the target. It trails and converges as eligible clients check in, with a ~±2% bucketing margin. Filter by
                the rollout's channel/platform to scope it.
              </p>
            </div>
          )}

          {/* Trend Graphs */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-8 mb-4 sm:mb-8">
            {/* Total Requests Trend */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Total Requests Trend</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {hasTrendData ? (
                  showSinglePointTrend ? (
                    <SinglePointTrendView
                      value={Number(dailyStats[0].total_requests ?? 0)}
                      color={lineChartConfig.requests}
                      dateLabel={singlePointDateLabel}
                    />
                  ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dailyStats}>
                      <defs>
                        <linearGradient id="requestsTrendArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={lineChartConfig.requests} stopOpacity={0.32} />
                          <stop offset="100%" stopColor={lineChartConfig.requests} stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_STROKE} />
                      <XAxis dataKey="date" stroke={CHART_AXIS_STROKE} tickFormatter={formatChartDate} />
                      <YAxis stroke={CHART_AXIS_STROKE} tickFormatter={(value) => formatNumber(value)} />
                      <Tooltip {...sharedTooltipProps} labelFormatter={(value) => formatChartDateLong(String(value))} />
                      <Area
                        type="monotoneX"
                        dataKey="total_requests"
                        stroke={lineChartConfig.requests}
                        strokeWidth={3}
                        fill="url(#requestsTrendArea)"
                        fillOpacity={1}
                        dot={false}
                        activeDot={{ r: 6, strokeWidth: 0, fill: lineChartConfig.requests }}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                        isAnimationActive={true}
                        animationDuration={700}
                        animationEasing="ease-out"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                  )
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Unique Clients Trend */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Unique Clients Trend</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {hasTrendData ? (
                  showSinglePointTrend ? (
                    <SinglePointTrendView
                      value={Number(dailyStats[0].unique_clients ?? 0)}
                      color={lineChartConfig.uniqueClients}
                      dateLabel={singlePointDateLabel}
                    />
                  ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dailyStats}>
                      <defs>
                        <linearGradient id="uniqueClientsTrendArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={lineChartConfig.uniqueClients} stopOpacity={0.32} />
                          <stop offset="100%" stopColor={lineChartConfig.uniqueClients} stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_STROKE} />
                      <XAxis dataKey="date" stroke={CHART_AXIS_STROKE} tickFormatter={formatChartDate} />
                      <YAxis stroke={CHART_AXIS_STROKE} tickFormatter={(value) => formatNumber(value)} />
                      <Tooltip {...sharedTooltipProps} labelFormatter={(value) => formatChartDateLong(String(value))} />
                      <Area
                        type="monotoneX"
                        dataKey="unique_clients"
                        stroke={lineChartConfig.uniqueClients}
                        strokeWidth={3}
                        fill="url(#uniqueClientsTrendArea)"
                        fillOpacity={1}
                        dot={false}
                        activeDot={{ r: 6, strokeWidth: 0, fill: lineChartConfig.uniqueClients }}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                        isAnimationActive={true}
                        animationDuration={700}
                        animationEasing="ease-out"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                  )
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Latest Version Users Trend */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Latest Version Users Trend</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {hasTrendData ? (
                  showSinglePointTrend ? (
                    <SinglePointTrendView
                      value={Number(dailyStats[0].clients_using_latest_version ?? 0)}
                      color={lineChartConfig.latestUsers}
                      dateLabel={singlePointDateLabel}
                    />
                  ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dailyStats}>
                      <defs>
                        <linearGradient id="latestUsersTrendArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={lineChartConfig.latestUsers} stopOpacity={0.32} />
                          <stop offset="100%" stopColor={lineChartConfig.latestUsers} stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_STROKE} />
                      <XAxis dataKey="date" stroke={CHART_AXIS_STROKE} tickFormatter={formatChartDate} />
                      <YAxis stroke={CHART_AXIS_STROKE} tickFormatter={(value) => formatNumber(value)} />
                      <Tooltip {...sharedTooltipProps} labelFormatter={(value) => formatChartDateLong(String(value))} />
                      <Area
                        type="monotoneX"
                        dataKey="clients_using_latest_version"
                        stroke={lineChartConfig.latestUsers}
                        strokeWidth={3}
                        fill="url(#latestUsersTrendArea)"
                        fillOpacity={1}
                        dot={false}
                        activeDot={{ r: 6, strokeWidth: 0, fill: lineChartConfig.latestUsers }}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                        isAnimationActive={true}
                        animationDuration={700}
                        animationEasing="ease-out"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                  )
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Outdated Clients Trend */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Outdated Clients Trend</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {hasTrendData ? (
                  showSinglePointTrend ? (
                    <SinglePointTrendView
                      value={Number(dailyStats[0].clients_outdated ?? 0)}
                      color={lineChartConfig.outdatedClients}
                      dateLabel={singlePointDateLabel}
                    />
                  ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dailyStats}>
                      <defs>
                        <linearGradient id="outdatedClientsTrendArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={lineChartConfig.outdatedClients} stopOpacity={0.32} />
                          <stop offset="100%" stopColor={lineChartConfig.outdatedClients} stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_STROKE} />
                      <XAxis dataKey="date" stroke={CHART_AXIS_STROKE} tickFormatter={formatChartDate} />
                      <YAxis stroke={CHART_AXIS_STROKE} tickFormatter={(value) => formatNumber(value)} />
                      <Tooltip {...sharedTooltipProps} labelFormatter={(value) => formatChartDateLong(String(value))} />
                      <Area
                        type="monotoneX"
                        dataKey="clients_outdated"
                        stroke={lineChartConfig.outdatedClients}
                        strokeWidth={3}
                        fill="url(#outdatedClientsTrendArea)"
                        fillOpacity={1}
                        dot={false}
                        activeDot={{ r: 6, strokeWidth: 0, fill: lineChartConfig.outdatedClients }}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                        isAnimationActive={true}
                        animationDuration={700}
                        animationEasing="ease-out"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                  )
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-8 mb-4 sm:mb-8">
            {/* Version Usage Chart */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Version Usage</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {data.versions?.usage ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.versions.usage}>
                      <defs>
                        <linearGradient id="versionUsageGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={chartColors[0]} stopOpacity={0.95} />
                          <stop offset="100%" stopColor={chartColors[4]} stopOpacity={0.85} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID_STROKE} />
                      <XAxis dataKey="version" stroke={CHART_AXIS_STROKE} />
                      <YAxis stroke={CHART_AXIS_STROKE} tickFormatter={(value) => formatNumber(value)} />
                      <Tooltip 
                        {...sharedTooltipProps}
                        cursor={false}
                      />
                      <Bar
                        dataKey="client_count"
                        fill="url(#versionUsageGradient)"
                        radius={[8, 8, 0, 0]}
                        activeBar={{
                          fill: chartColors[0],
                          stroke: 'none'
                        }}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Platform Distribution Chart */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Platform Distribution</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {data.platforms ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={data.platforms}
                        dataKey="client_count"
                        nameKey="platform"
                        cx="50%"
                        cy="45%"
                        innerRadius={50}
                        outerRadius={86}
                        paddingAngle={2}
                        cornerRadius={6}
                        label={false}
                        labelLine={false}
                      >
                        {data.platforms.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip {...sharedTooltipProps} />
                      <Legend
                        verticalAlign="bottom"
                        iconType="circle"
                        formatter={(value) => <span style={{ color: 'var(--theme-primary)' }}>{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Architecture Distribution Chart */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Architecture Distribution</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {data.architectures ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={data.architectures}
                        dataKey="client_count"
                        nameKey="arch"
                        cx="50%"
                        cy="45%"
                        innerRadius={50}
                        outerRadius={86}
                        paddingAngle={2}
                        cornerRadius={6}
                        label={false}
                        labelLine={false}
                      >
                        {data.architectures.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip {...sharedTooltipProps} />
                      <Legend
                        verticalAlign="bottom"
                        iconType="circle"
                        formatter={(value) => <span style={{ color: 'var(--theme-primary)' }}>{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>

            {/* Channel Distribution Chart */}
            <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
              <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Channel Distribution</h3>
              <div className="h-60 sm:h-80 min-w-0 overflow-x-auto">
                {data.channels ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={data.channels}
                        dataKey="client_count"
                        nameKey="channel"
                        cx="50%"
                        cy="45%"
                        innerRadius={50}
                        outerRadius={86}
                        paddingAngle={2}
                        cornerRadius={6}
                        label={false}
                        labelLine={false}
                      >
                        {data.channels.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip {...sharedTooltipProps} />
                      <Legend
                        verticalAlign="bottom"
                        iconType="circle"
                        formatter={(value) => <span style={{ color: 'var(--theme-primary)' }}>{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <NoDataMessage />
                )}
              </div>
            </div>
          </div>

          {/* Version Table */}
          <div className={`${PANEL_CLASS} p-3 sm:p-6`}>
            <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-4 text-theme-primary">Version Details</h3>
            <div className="overflow-x-auto">
              {data.versions?.usage ? (
                <table className="min-w-full divide-y divide-theme-card-hover">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-theme-primary uppercase tracking-wider">Version</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-theme-primary uppercase tracking-wider">Client Count</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-theme-primary uppercase tracking-wider">% of Total</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-card-hover">
                    {data.versions.usage.map((version) => (
                      <tr key={version.version} className="hover:bg-theme-card-hover transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap text-theme-primary">{version.version}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-theme-primary">{version.client_count}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-theme-primary">
                          {((version.client_count / (data.summary?.unique_clients || 1)) * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <NoDataMessage />
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}; 