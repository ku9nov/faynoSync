"use client";
import React from "react";
import { Header } from "@/components/layout/Header";
import { Sidebar } from "@/components/layout/Sidebar";
import { Dashboard } from "@/components/Dashboard";
import { UploadModal } from "@/components/modals/UploadModal";
import { ChangelogModal } from "@/components/modals/ChangelogModal";
import { CreateAppModal } from "@/components/modals/CreateAppModal";
import { ChangelogEntry } from "@/hooks/use-query/useAppsQuery";
import { useAppDataQuery } from "@/hooks/use-query/useAppDataQuery";
import { AppLogo } from "@/components/common/AppLogo";
import { useParams, useNavigate } from "react-router-dom";

export const HomePage = () => {
  const { appName } = useParams();
  const navigate = useNavigate();
  const [showUploadModal, setShowUploadModal] = React.useState(false);
  const [showCreateAppModal, setShowCreateAppModal] = React.useState(false);
  const [selectedApp, setSelectedApp] = React.useState<string | null>(appName || null);
  const [showChangelogModal, setShowChangelogModal] = React.useState(false);
  const [selectedVersion, setSelectedVersion] = React.useState<string | null>(null);
  const [selectedChangelog, setSelectedChangelog] = React.useState<ChangelogEntry[]>([]);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(false);

  React.useEffect(() => {
    setSelectedApp(appName || null);
  }, [appName]);

  const toggleUploadModal = () => {
    setShowUploadModal(!showUploadModal);
  };

  const toggleCreateAppModal = () => {
    setShowCreateAppModal(!showCreateAppModal);
  };

  const handleAppClick = (appName: string) => {
    setSelectedApp(appName);
    navigate(`/applications/${appName}`);
  };

  const handleBackClick = () => {
    setSelectedApp(null);
    navigate('/applications');
  };

  const handleChangelogClick = (version: string, changelog: ChangelogEntry[]) => {
    setSelectedVersion(version);
    setSelectedChangelog(changelog);
    setShowChangelogModal(true);
  };

  const closeChangelogModal = () => {
    setShowChangelogModal(false);
    setSelectedVersion(null);
    setSelectedChangelog([]);
  };

  const handleCreateAppSuccess = () => {
    setRefreshKey(prev => prev + 1);
  };

  const handleSearchChange = (term: string) => {
    setSearchTerm(term);
  };

  const { data: appData } = useAppDataQuery(selectedApp);

  const appTitleContent = selectedApp ? (
    <div className="flex items-center gap-4 min-w-0">
      <div className="relative w-11 h-11 flex-shrink-0">
        <AppLogo name={selectedApp} logo={appData?.Logo} className="w-11 h-11" />
        {appData?.Private && (
          <div className="absolute -bottom-1 -right-1 rounded-full bg-red-500 p-1">
            <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
          </div>
        )}
      </div>
      <h2 className="header-title mb-0 truncate" title={selectedApp}>
        {selectedApp}
      </h2>
    </div>
  ) : undefined;

  return (
    <div className="min-h-screen bg-theme-gradient font-sans">
      <div className="flex">
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
        <main className="flex-1 min-w-0 p-8">
          <Header
            title="Applications"
            titleContent={appTitleContent}
            onCreateClick={toggleUploadModal}
            createButtonText="Upload the app"
            additionalButton={
              <button
                onClick={toggleCreateAppModal}
                className="header-additional-btn p-2.5 md:px-4 md:py-2 font-sans"
                aria-label="Create app"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
                </svg>
                <span className="hidden md:inline ml-2">Create app</span>
              </button>
            }
            onSearchChange={handleSearchChange}
            hideSearch={!!selectedApp}
            onMenuClick={() => setIsSidebarOpen(true)}
          />
          <Dashboard 
            selectedApp={selectedApp}
            onAppClick={handleAppClick}
            onChangelogClick={handleChangelogClick}
            onBackClick={handleBackClick}
            refreshKey={refreshKey}
            searchTerm={searchTerm}
          />
        </main>
      </div>
      {showUploadModal && (
        <UploadModal onClose={toggleUploadModal} />
      )}
      {showCreateAppModal && (
        <CreateAppModal 
          onClose={toggleCreateAppModal} 
          onSuccess={handleCreateAppSuccess}
        />
      )}
      {showChangelogModal && selectedVersion && selectedApp && (
        <ChangelogModal
          appName={selectedApp}
          version={selectedVersion}
          changelog={selectedChangelog}
          onClose={closeChangelogModal}
        />
      )}
    </div>
  );
};
