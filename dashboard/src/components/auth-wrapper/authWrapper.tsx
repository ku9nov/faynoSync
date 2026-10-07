import { FC, PropsWithChildren } from 'react';

export const AuthWrapper: FC<PropsWithChildren> = ({ children }) => {
  return (
    <div className='flex h-screen max-h-full font-sans bg-theme-auth-gradient'>
      <div className='flex-1 flex flex-col relative overflow-hidden'>
        <main className='flex-1 flex items-center justify-center'>
          {children}
        </main>
        <div className='absolute inset-0 pointer-events-none'>
          <svg
            className='absolute bottom-0 left-0 w-full'
            viewBox='0 0 1440 320'
            preserveAspectRatio='none'>
            <path
              fill='rgba(255, 255, 255, 0.1)'
              fillOpacity='1'
              d='M0,64L48,80C96,96,192,128,288,128C384,128,480,96,576,90.7C672,85,768,107,864,128C960,149,1056,171,1152,165.3C1248,160,1344,128,1392,112L1440,96L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z'></path>
          </svg>
          <svg
            className='absolute bottom-0 left-0 w-full'
            viewBox='0 0 1440 320'
            preserveAspectRatio='none'>
            <path
              fill='rgba(255, 255, 255, 0.05)'
              fillOpacity='1'
              d='M0,160L48,170.7C96,181,192,203,288,202.7C384,203,480,181,576,165.3C672,149,768,139,864,154.7C960,171,1056,213,1152,218.7C1248,224,1344,192,1392,176L1440,160L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z'></path>
          </svg>
        </div>
      </div>
    </div>
  );
};
