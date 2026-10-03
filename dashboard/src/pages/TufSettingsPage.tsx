import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { TufSettings } from '@/components/settings/TufSettings';

export const TufSettingsPage = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const navigate = useNavigate();

  const menuItems = [
    { id: 'users', label: 'Users', icon: 'fa-users' },
    { id: 'tuf', label: 'TUF', icon: 'fa-shield-alt' },
  ];

  const handlePageChange = (page: 'users' | 'tuf') => {
    if (page === 'users') {
      navigate('/settings');
    } else {
      navigate('/settings/tuf');
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
                      onClick={() => handlePageChange(item.id as 'users' | 'tuf')}
                      className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                        item.id === 'tuf'
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
                <TufSettings />
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

