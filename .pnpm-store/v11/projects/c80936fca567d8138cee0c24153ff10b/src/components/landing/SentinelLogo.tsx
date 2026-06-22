import React from 'react';

const BrandLogo: React.FC<{ className?: string }> = ({ className = "w-12 h-12" }) => {
  return (
    <div className={`relative ${className}`}>
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
      >
        {/* Hexagonal Node Background */}
        <path
          d="M50 5L89 27.5V72.5L50 95L11 72.5V27.5L50 5Z"
          className="fill-surface-container stroke-secondary/20"
          strokeWidth="1"
        />
        
        {/* Neural Circuits */}
        <path
          d="M30 40L50 30L70 40M30 60L50 70L70 60"
          className="stroke-cyan-500/50"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
        <circle cx="30" cy="40" r="1.5" className="fill-cyan-400 shadow-sm" />
        <circle cx="70" cy="40" r="1.5" className="fill-cyan-400 shadow-sm" />
        <circle cx="30" cy="60" r="1.5" className="fill-cyan-400 shadow-sm" />
        <circle cx="70" cy="60" r="1.5" className="fill-cyan-400 shadow-sm" />
        <circle cx="50" cy="30" r="2" className="fill-purple-500 shadow-lg shadow-purple-500/50" />
        <circle cx="50" cy="70" r="2" className="fill-purple-500 shadow-lg shadow-purple-500/50" />

        {/* APK Cube / Shield Hybrid */}
        <path
          d="M50 20L75 30V55C75 70 50 85 50 85C50 85 25 70 25 55V30L50 20Z"
          className="fill-secondary/10 stroke-secondary"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        
        {/* Inner Cube Detail */}
        <path
          d="M50 20L50 45M50 45L75 30M50 45L25 30"
          className="stroke-secondary/40"
          strokeWidth="1"
        />
        
        {/* Pulse Effect */}
        <path
          d="M50 5L89 27.5V72.5L50 95L11 72.5V27.5L50 5Z"
          className="stroke-cyan-400/30 animate-pulse-slow"
          strokeWidth="0.5"
        />
      </svg>
    </div>
  );
};

export default BrandLogo;
