const Footer = () => {
  return (
    <footer className="w-full py-section-gap px-container-padding-desktop flex flex-col md:flex-row justify-between items-center gap-base border-t border-white/5 bg-background">
      <div className="flex flex-col gap-2">
        <span className="font-display-xl text-title-md tracking-tighter text-on-surface">
          SENTINEL AI
        </span>
        <p className="font-label-sm text-label-sm text-on-surface-variant opacity-60">
          © 2024 SENTINEL AI. ALL RIGHTS RESERVED.
        </p>
      </div>
      <div className="flex flex-wrap justify-center gap-gutter">
        <a
          href="#"
          className="text-on-surface-variant font-label-sm text-label-sm hover:text-on-surface transition-colors"
        >
          Privacy Protocol
        </a>
        <a
          href="#"
          className="text-on-surface-variant font-label-sm text-label-sm hover:text-on-surface transition-colors"
        >
          Neural Terms
        </a>
        <a
          href="#"
          className="text-on-surface-variant font-label-sm text-label-sm hover:text-on-surface transition-colors"
        >
          System Status
        </a>
        <a
          href="#"
          className="text-on-surface-variant font-label-sm text-label-sm hover:text-on-surface transition-colors"
        >
          Intelligence API
        </a>
      </div>
      <div className="flex items-center gap-4 text-primary">
        <span className="text-label-sm font-label-sm">SYSTEM STABLE</span>
        <div className="w-2 h-2 rounded-full bg-tertiary animate-pulse"></div>
      </div>
    </footer>
  )
}

export default Footer
