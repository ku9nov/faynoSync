import { FC, PropsWithChildren } from 'react';
import { AnimatedBanner } from '@/components/auth-logo/AnimatedBanner';

export const AuthLogo: FC<PropsWithChildren> = () => {
  return (
    <div className='w-full md:w-2/3 lg:w-3/4 flex items-center justify-center'>
      <AnimatedBanner />
    </div>
  );
};
