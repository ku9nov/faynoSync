import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { UsersSettings } from '@/components/settings/UsersSettings';
import { TufSettings } from '@/components/settings/TufSettings';
import { TokenSettings } from '@/components/settings/TokenSettings';

type SettingsPage = 'users' | 'tokens' | 'tuf';

export const SettingsPage = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  
  // Determine current page from URL or default to 'users'
  const getCurrentPage = (): SettingsPage => {
    if (location.pathname === '/settings/tuf') {
      return 'tuf';
    }
    if (location.pathname === '/settings/tokens') {
      return 'tokens';
    }
    return 'users';
  };
  
  const [currentPage, setCurrentPage] = useState<SettingsPage>(getCurrentPage());

  // Update current page when location changes
  useEffect(() => {
    const page = getCurrentPage();
    setCurrentPage(page);
  }, [location.pathname]);

  const menuItems = [
    { id: 'users' as SettingsPage, label: 'Users', icon: 'fa-users' },
    { id: 'tokens' as SettingsPage, label: 'CI/CD Tokens', icon: 'fa-key' },
    { id: 'tuf' as SettingsPage, label: 'TUF', icon: 'fa-shield-alt' },
  ];

  const handlePageChange = (page: SettingsPage) => {
    setCurrentPage(page);
    if (page === 'tuf') {
      navigate('/settings/tuf');
    } else if (page === 'tokens') {
      navigate('/settings/tokens');
    } else {
      navigate('/settings');
    }
  };

  return (
    <div className="min-h-screen bg-theme-gradient font-sans">
      <div className="flex flex-col lg:flex-row">
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
        <main className="flex-1 min-w-0 p-2 sm:p-4 md:p-8">
          <Header
            title="Settings"
            onMenuClick={() => setIsSidebarOpen(true)}
            onCreateClick={() => {}}
            createButtonText=""
            hideSearch={true}
          />
          
          <div className="mt-4 sm:mt-8">
            <div className="bg-theme-card rounded-lg shadow-md p-4 sm:p-6">
              {/* Navigation Tabs */}
              <div className="mb-6 border-b border-theme-card-hover">
                <nav className="flex space-x-4">
                  {menuItems.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => handlePageChange(item.id)}
                      className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                        currentPage === item.id
                          ? 'bg-theme-button-primary bg-opacity-50 text-theme-primary border-b-2 border-blue-500'
                          : 'text-theme-primary opacity-70 hover:opacity-100 hover:bg-theme-card-hover'
                      }`}
                    >
                      <i className={`fas ${item.icon} mr-2`}></i>
                      {item.label}
                    </button>
                  ))}
                </nav>
              </div>

              {/* Content */}
              <div className="mt-6">
                {currentPage === 'users' && <UsersSettings />}
                {currentPage === 'tokens' && <TokenSettings />}
                {currentPage === 'tuf' && <TufSettings />}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

