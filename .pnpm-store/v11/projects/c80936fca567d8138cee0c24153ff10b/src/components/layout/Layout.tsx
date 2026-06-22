import { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import Header from './Header'
import SystemHealthStrip from './SystemHealthStrip'
import Footer from './Footer'

interface LayoutProps {
  children: ReactNode
}

const Layout = ({ children }: LayoutProps) => {
  const location = useLocation()
  const isDeviceLabRoute = location.pathname.startsWith('/device-lab')

  return (
    <div className="min-h-screen bg-background text-on-surface">
      <Header />
      <SystemHealthStrip />
      <main className={`relative pt-[7.5rem] ${isDeviceLabRoute ? 'min-h-screen pb-0' : 'min-h-screen pb-section-gap'}`}>
        {children}
      </main>
      {!isDeviceLabRoute && <Footer />}
    </div>
  )
}

export default Layout
