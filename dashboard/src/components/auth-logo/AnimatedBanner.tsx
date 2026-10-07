import React, { useEffect, useRef, useState } from 'react';
import styles from '@/components/auth-logo/styles.module.css';

interface AnimatedBannerProps {
  fadeOut?: boolean; // If true, banner fades out after animation
  onAnimationEnd?: () => void;
}

const ANIMATION_DURATION = 8000; // ms, total duration of all steps

// Custom hook to detect mobile
function useIsMobile(breakpoint = 900) {
  const [isMobile, setIsMobile] = useState(false);
  useEffect(() => {
    function handleResize() {
      setIsMobile(window.innerWidth <= breakpoint);
    }
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [breakpoint]);
  return isMobile;
}

export const AnimatedBanner: React.FC<AnimatedBannerProps> = ({ fadeOut = false, onAnimationEnd }) => {
  const [step, setStep] = useState(0); // 0: nothing, 1: spiral, 2: text, 3: arrows, 4: done
  const [hide, setHide] = useState(false);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const isMobile = useIsMobile(900);

  useEffect(() => {
    // Step-by-step animation
    timerRef.current = setTimeout(() => setStep(1), 100); // Spiral in
    const t1 = setTimeout(() => setStep(2), 900); // Text fade in
    const t2 = setTimeout(() => setStep(3), 1800); // Arrows slide in
    const t3 = setTimeout(() => setStep(4), ANIMATION_DURATION); // Animation done
    if (fadeOut) {
      const t4 = setTimeout(() => setHide(true), ANIMATION_DURATION + 800);
      return () => { if (timerRef.current) clearTimeout(timerRef.current); clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); clearTimeout(t4); };
    }
    return () => { if (timerRef.current) clearTimeout(timerRef.current); clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
  }, [fadeOut]);

  useEffect(() => {
    if (step === 4 && onAnimationEnd) onAnimationEnd();
  }, [step, onAnimationEnd]);

  // Choose x coordinates based on device
  const faynoX = isMobile ? '20%' : 140;
  const syncX = isMobile ? '55%' : 570;

  return (
    <div
      className={[
        styles.bannerRoot,
        step >= 1 ? styles.spiralVisible : '',
        step >= 2 ? styles.textVisible : '',
        step >= 3 ? styles.arrowsVisible : '',
        step >= 4 ? styles.static : '',
        hide ? styles.fadeOut : '',
      ].join(' ')}
      aria-label="FaynoSync animated logo banner"
    >
      <svg
        viewBox="0 0 1050 340"
        className={styles.bannerSvg}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
        style={{ width: '100%', height: 'auto', maxWidth: 1180 }}
        preserveAspectRatio="xMidYMid meet"
      >
        <g className={styles.orbits}>
          <path d="M188 222 C 318 68, 560 42, 752 132" stroke="url(#orbitGradient)" strokeWidth="2" strokeLinecap="round" strokeDasharray="10 18" />
          <path d="M868 116 C 732 278, 486 306, 288 206" stroke="url(#orbitGradient2)" strokeWidth="2" strokeLinecap="round" strokeDasharray="8 16" />
        </g>
        {/* Purple Up Arrow */}
        <g className={styles.arrowUp}>
          <path d="M98 267 C 216 114, 404 69, 622 139 L610 100 L692 160 L596 191 L615 158 C 408 94, 238 138, 126 279 C 119 288, 105 280, 98 267 Z" fill="url(#arrowUpGradient)" filter="url(#softShadow)" />
        </g>
        {/* Orange Down Arrow */}
        <g className={styles.arrowDown}>
          <path d="M952 72 C 834 226, 646 271, 428 201 L440 240 L358 180 L454 149 L435 182 C 642 247, 812 203, 924 61 C 931 52, 945 60, 952 72 Z" fill="url(#arrowDownGradient)" filter="url(#softShadow)" />
        </g>
        {/* Spiral */}
        <g className={styles.spiral}>
          <circle cx="500" cy="170" r="48" fill="url(#spiralGradient)" filter="url(#logoShadow)" />
          <path d="M500 170 m-37,0 a37,37 0 1,1 74,0 a37,37 0 1,1 -74,0" stroke="url(#spiralStroke)" strokeWidth="7" fill="none" />
          <path d="M500 170 m-25,0 a25,25 0 1,1 50,0 a25,25 0 1,1 -50,0" stroke="url(#spiralStroke2)" strokeWidth="4.5" fill="none" />
        </g>
        {/* Text */}
        <g className={styles.text}>
          <text className={styles.word} x={faynoX} y="188" fontFamily="Inter, Montserrat, Arial, sans-serif" fontWeight="900" fontSize="76" fill="url(#textGradient)" letterSpacing="7">FAYNO</text>
          <text className={styles.word} x={syncX} y="188" fontFamily="Inter, Montserrat, Arial, sans-serif" fontWeight="900" fontSize="76" fill="url(#textGradient2)" letterSpacing="7">SYNC</text>
        </g>
        <defs>
          <filter id="softShadow" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="14" stdDeviation="14" floodColor="#271154" floodOpacity="0.22" />
          </filter>
          <filter id="logoShadow" x="-40%" y="-40%" width="180%" height="180%">
            <feDropShadow dx="0" dy="18" stdDeviation="18" floodColor="#6D28D9" floodOpacity="0.35" />
            <feDropShadow dx="0" dy="8" stdDeviation="10" floodColor="#FF7A45" floodOpacity="0.22" />
          </filter>
          <linearGradient id="orbitGradient" x1="188" y1="222" x2="752" y2="132" gradientUnits="userSpaceOnUse">
            <stop stopColor="#7C3AED" stopOpacity="0" />
            <stop offset="0.5" stopColor="#7C3AED" stopOpacity="0.4" />
            <stop offset="1" stopColor="#F97316" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="orbitGradient2" x1="868" y1="116" x2="288" y2="206" gradientUnits="userSpaceOnUse">
            <stop stopColor="#F97316" stopOpacity="0" />
            <stop offset="0.5" stopColor="#F97316" stopOpacity="0.38" />
            <stop offset="1" stopColor="#7C3AED" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="arrowUpGradient" x1="108" y1="256" x2="682" y2="158" gradientUnits="userSpaceOnUse">
            <stop stopColor="#C4B5FD" />
            <stop offset="0.45" stopColor="#8B5CF6" />
            <stop offset="1" stopColor="#5B21B6" />
          </linearGradient>
          <linearGradient id="arrowDownGradient" x1="942" y1="82" x2="368" y2="184" gradientUnits="userSpaceOnUse">
            <stop stopColor="#FFD18A" />
            <stop offset="0.45" stopColor="#FB923C" />
            <stop offset="1" stopColor="#EA580C" />
          </linearGradient>
          <radialGradient id="spiralGradient" cx="0.5" cy="0.5" r="0.7">
            <stop offset="0%" stopColor="#FFF7ED" />
            <stop offset="36%" stopColor="#FDBA74" />
            <stop offset="72%" stopColor="#A855F7" />
            <stop offset="100%" stopColor="#6D28D9" />
          </radialGradient>
          <linearGradient id="spiralStroke" x1="463" y1="170" x2="537" y2="170" gradientUnits="userSpaceOnUse">
            <stop stopColor="#FFFFFF" stopOpacity="0.92" />
            <stop offset="0.5" stopColor="#FFEDD5" />
            <stop offset="1" stopColor="#C4B5FD" />
          </linearGradient>
          <linearGradient id="spiralStroke2" x1="475" y1="170" x2="525" y2="170" gradientUnits="userSpaceOnUse">
            <stop stopColor="#7C3AED" />
            <stop offset="1" stopColor="#FB923C" />
          </linearGradient>
          <linearGradient id="textGradient" x1="120" y1="188" x2="448" y2="188" gradientUnits="userSpaceOnUse">
            <stop stopColor="#3B0764" />
            <stop offset="0.45" stopColor="#7C3AED" />
            <stop offset="1" stopColor="#A855F7" />
          </linearGradient>
          <linearGradient id="textGradient2" x1="570" y1="188" x2="884" y2="188" gradientUnits="userSpaceOnUse">
            <stop stopColor="#FFB86C" />
            <stop offset="0.42" stopColor="#F97316" />
            <stop offset="1" stopColor="#7C2D12" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
};

export default AnimatedBanner; 