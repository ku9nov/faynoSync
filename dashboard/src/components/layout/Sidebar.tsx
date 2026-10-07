import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import '@/styles/sidebar.css';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const currentPath = location.pathname.split('/')[1] || 'applications';

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;

    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = previousOverflow || '';
    }

    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [isOpen]);

  const getButtonClass = (page: string) => {
    const baseClass = "sidebar-nav-button flex items-center";
    return page === currentPath
      ? `${baseClass} active`
      : baseClass;
  };

  const handleNavigation = (path: string) => {
    navigate(`/${path}`);
    onClose?.(); // close drawer on mobile after navigation
  };

  // Drawer for mobile
  const Drawer = () => (
    <div className={`fixed inset-0 z-200 flex md:hidden transition-all duration-300 ${isOpen ? '' : 'pointer-events-none'}`}> 
      {/* Overlay */}
      <div
        className={`fixed inset-0 sidebar-drawer-overlay transition-opacity duration-300 ${isOpen ? 'opacity-100' : 'opacity-0'}`}
        onClick={onClose}
        aria-label="Close menu overlay"
      />
      {/* Drawer panel */}
      <aside className={`relative w-64 max-w-[80vw] h-full sidebar-drawer-panel transform transition-transform duration-300 ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <div className="p-6 pt-3">
          <div className="mb-3 flex items-center justify-between w-full">
            <div 
              onClick={() => { navigate('/applications'); onClose?.(); }}
              className="w-full cursor-pointer sidebar-logo"
            >
              <img
                src={`${import.meta.env.BASE_URL}banner-small.png`}
                alt="FaynoSync Logo"
                className="w-full h-[80px] object-contain rounded-lg"
              />
            </div>
            <button
              className="ml-2 sidebar-close-button"
              aria-label="Close menu"
              onClick={onClose}
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <nav>
            <button 
              className={getButtonClass('applications')}
              onClick={() => handleNavigation('applications')}
            >
              <i className="fas fa-th-large"></i>
              <span>Applications</span>
            </button>
            <button 
              className={getButtonClass('channels')}
              onClick={() => handleNavigation('channels')}
            >
              <i className="fas fa-broadcast-tower"></i>
              <span>Channels</span>
            </button>
            <button 
              className={getButtonClass('platforms')}
              onClick={() => handleNavigation('platforms')}
            >
              <i className="fas fa-desktop"></i>
              <span>Platforms</span>
            </button>
            <button 
              className={getButtonClass('architectures')}
              onClick={() => handleNavigation('architectures')}
            >
              <i className="fas fa-microchip"></i>
              <span>Architectures</span>
            </button>
            <button
              className={getButtonClass('statistics')}
              onClick={() => handleNavigation('statistics')}
            >
              <i className="fas fa-chart-bar"></i>
              <span>Statistics</span>
            </button>
            <button
              className={getButtonClass('reports')}
              onClick={() => handleNavigation('reports')}
            >
              <i className="fas fa-flag"></i>
              <span>Reports</span>
            </button>
          </nav>
        </div>
      </aside>
    </div>
  );

  return (
    <>
      {/* Drawer only on mobile */}
      <Drawer />
      {/* Sidebar only on desktop */}
      <aside className="hidden md:block w-64 min-h-screen sidebar">
        <div className="p-6 pt-3">
          <div className="mb-3 flex items-center justify-center w-full">
            <div 
              onClick={() => navigate('/applications')}
              className="w-full cursor-pointer sidebar-logo"
            >
              <img
                src={`${import.meta.env.BASE_URL}banner-small.png`}
                alt="FaynoSync Logo"
                className="w-full h-[80px] object-contain rounded-lg"
              />
            </div>
          </div>
          <nav>
            <button 
              className={getButtonClass('applications')}
              onClick={() => handleNavigation('applications')}
            >
              <i className="fas fa-th-large"></i>
              <span>Applications</span>
            </button>
            <button 
              className={getButtonClass('channels')}
              onClick={() => handleNavigation('channels')}
            >
              <i className="fas fa-broadcast-tower"></i>
              <span>Channels</span>
            </button>
            <button 
              className={getButtonClass('platforms')}
              onClick={() => handleNavigation('platforms')}
            >
              <i className="fas fa-desktop"></i>
              <span>Platforms</span>
            </button>
            <button 
              className={getButtonClass('architectures')}
              onClick={() => handleNavigation('architectures')}
            >
              <i className="fas fa-microchip"></i>
              <span>Architectures</span>
            </button>
            <button
              className={getButtonClass('statistics')}
              onClick={() => handleNavigation('statistics')}
            >
              <i className="fas fa-chart-bar"></i>
              <span>Statistics</span>
            </button>
            <button
              className={getButtonClass('reports')}
              onClick={() => handleNavigation('reports')}
            >
              <i className="fas fa-flag"></i>
              <span>Reports</span>
            </button>
          </nav>
        </div>
      </aside>
    </>
  );
}; 