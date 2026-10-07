import React, { useEffect, useState } from 'react';
import { getAppInitials, getAppTileStyle } from '@/utils/appLogo';

interface AppLogoProps {
  name: string;
  logo?: string | null;
  className?: string;
  textClassName?: string;
}

export const AppLogo: React.FC<AppLogoProps> = ({
  name,
  logo,
  className = 'w-12 h-12',
  textClassName = 'text-base',
}) => {
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setFailed(false);
  }, [logo]);

  if (logo && !failed) {
    return (
      <img
        src={logo}
        alt={`${name} logo`}
        loading="lazy"
        onError={() => setFailed(true)}
        className={`${className} rounded-lg object-contain bg-violet-950/30`}
      />
    );
  }

  return (
    <span
      aria-hidden="true"
      title={name}
      className={`${className} ${getAppTileStyle(name)} ${textClassName} flex items-center justify-center rounded-lg border font-extrabold tracking-tight`}
    >
      {getAppInitials(name)}
    </span>
  );
};
