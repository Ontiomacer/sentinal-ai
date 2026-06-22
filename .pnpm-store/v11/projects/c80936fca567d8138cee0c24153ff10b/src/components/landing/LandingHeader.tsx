import React from 'react';
import { Link } from 'react-router-dom';
import Logo from './SentinelLogo';

const LandingHeader: React.FC = () => {
  return (
    <header className="fixed top-0 left-0 w-full z-[100] px-container-padding-desktop py-6">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <Link to="/" className="flex items-center gap-3 group">
          <Logo className="w-10 h-10 group-hover:scale-110 transition-transform" />
          <span className="font-display-xl text-xl tracking-tighter text-white group-hover:text-cyan-400 transition-colors">
            SENTINEL AI
          </span>
        </Link>

        <nav className="hidden md:flex items-center gap-8">
          {[
            { label: 'Features', id: 'features' },
            { label: 'Differentiators', id: 'differentiators' },
            { label: 'Intelligence', id: 'demo' },
            { label: 'Demo', id: 'demo' }
          ].map((item) => (
            <a
              key={item.label}
              href={`#${item.id}`}
              className="text-sm font-label-sm text-on-surface-variant hover:text-white transition-colors uppercase tracking-widest"
            >
              {item.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-4">
          <Link
            to="/cases"
            className="px-5 py-2 rounded border border-white/10 bg-white/5 backdrop-blur-md text-white font-bold text-xs tracking-tight hover:bg-white/10 transition-all"
          >
            Open Console
          </Link>
          <button className="px-5 py-2 rounded bg-cyan-600 text-white font-bold text-xs tracking-tight hover:bg-cyan-500 transition-all shadow-lg shadow-cyan-500/20">
            Sign In
          </button>
        </div>
      </div>
    </header>
  );
};

export default LandingHeader;
