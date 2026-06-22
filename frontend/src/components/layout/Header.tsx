import { Link, useLocation } from 'react-router-dom'
import { SignInButton, SignUpButton, UserButton, useUser } from '@clerk/clerk-react'
import { useEffect, useState } from 'react'

const Header = () => {
  const location = useLocation()
  const { isSignedIn, user } = useUser()
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return localStorage.getItem('sentinel-theme') === 'light' ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.classList.toggle('theme-light', theme === 'light')
    localStorage.setItem('sentinel-theme', theme)
  }, [theme])

  const isActive = (path: string) => location.pathname === path
  const isInPath = (prefix: string) => location.pathname.startsWith(prefix)

  const navLinks = [
    { to: '/cases', label: 'Cases', active: location.pathname === '/' || location.pathname === '/cases' || isInPath('/cases/') },
    { to: '/threat-ops', label: 'Threat Ops', active: isInPath('/threat-ops') },
    { to: '/neural-lab', label: 'Neural Lab', active: isInPath('/neural-lab') },
    { to: '/device-lab', label: 'Device Lab', active: isInPath('/device-lab') },
    { to: '/mcp', label: 'MCP Hub', active: isInPath('/mcp') },
    { to: '/history', label: 'History', active: isActive('/history') },
    { to: '/cli', label: 'CLI', active: isActive('/cli') },
  ]

  return (
    <header className="fixed top-0 w-full z-50 flex justify-between items-center px-container-padding-desktop py-4 bg-surface/60 backdrop-blur-xl border-b border-white/10 shadow-sm">
      <div className="flex items-center gap-base">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-8 h-8 rounded bg-secondary/20 border border-secondary/40 flex items-center justify-center group-hover:bg-secondary/30 transition-all">
            <span className="material-symbols-outlined text-secondary text-lg">shield</span>
          </div>
          <span className="font-display-xl text-title-md tracking-tighter text-on-surface group-hover:text-primary transition-colors">
            SENTINEL AI
          </span>
        </Link>
        <nav className="ml-10 hidden md:flex items-center gap-1">
          {navLinks.map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className={`px-3 py-1.5 rounded font-label-sm text-label-sm transition-all duration-200 ${
                link.active
                  ? 'bg-secondary/15 text-secondary font-bold'
                  : 'text-on-surface-variant font-medium hover:text-primary hover:bg-white/5'
              }`}
            >
              {link.label}
            </Link>
          ))}
        </nav>
      </div>
      <div className="flex items-center gap-4">
        <button
          onClick={() => setTheme((value) => value === 'dark' ? 'light' : 'dark')}
          className="border border-white/10 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.16em] text-on-surface-variant hover:text-on-surface"
          title="Toggle global theme"
        >
          {theme === 'dark' ? 'Dark' : 'Light'}
        </button>
        <div className="relative hidden lg:block">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant/40 text-sm">search</span>
          <input
            className="bg-surface-container-lowest border-none border-b border-outline text-label-sm font-label-sm focus:ring-1 focus:ring-secondary w-56 pl-9 pr-4 py-2 transition-all rounded"
            placeholder="QUERY THREAT DATABASE..."
            type="text"
          />
        </div>
        <div className="flex gap-3 items-center">
          <button className="relative p-1.5 rounded hover:bg-white/5 transition-colors" title="Notifications">
            <span className="material-symbols-outlined text-on-surface-variant hover:text-primary transition-colors text-xl">
              notifications
            </span>
          </button>

          {isSignedIn ? (
            <div className="flex items-center gap-3">
              <span className="hidden lg:block font-mono text-[10px] text-on-surface-variant/60 uppercase tracking-widest">
                {user?.firstName || user?.username || 'Analyst'}
              </span>
              <UserButton
                appearance={{
                  elements: {
                    avatarBox: "w-8 h-8"
                  }
                }}
              />
            </div>
          ) : (
            <div className="flex gap-2">
              <SignInButton mode="modal">
                <button className="px-4 py-2 text-label-sm font-label-sm text-on-surface-variant hover:text-primary transition-colors">
                  SIGN IN
                </button>
              </SignInButton>
              <SignUpButton mode="modal">
                <button className="px-4 py-2 bg-secondary text-on-secondary rounded font-label-sm text-label-sm hover:opacity-90 transition-all">
                  SIGN UP
                </button>
              </SignUpButton>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header
