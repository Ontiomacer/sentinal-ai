import React, { useEffect } from 'react';
import Hero from '../components/landing/Hero';
import LandingPipeline from '../components/landing/LandingPipeline';
import Differentiators from '../components/landing/Differentiators';
import DemoSection from '../components/landing/DemoSection';
import LandingHeader from '../components/landing/LandingHeader';
import Footer from '../components/layout/Footer';

const LandingPage: React.FC = () => {
  // Add some global styles for the landing page specifically
  useEffect(() => {
    document.documentElement.classList.add('landing-page');
    document.documentElement.style.scrollBehavior = 'smooth';
    return () => {
      document.documentElement.classList.remove('landing-page');
      document.documentElement.style.scrollBehavior = 'auto';
    };
  }, []);

  return (
    <div className="flex flex-col min-h-screen bg-background text-on-surface selection:bg-cyan-500/30">
      <LandingHeader />
      
      <main className="flex-grow">
        <div id="hero"><Hero /></div>
        <div id="features"><LandingPipeline /></div>
        <div id="differentiators"><Differentiators /></div>
        <div id="demo"><DemoSection /></div>
        
        {/* Call to Action Final */}
        <section className="py-24 px-container-padding-desktop bg-gradient-to-b from-surface-container-lowest to-background text-center relative overflow-hidden">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[300px] bg-purple-500/10 blur-[120px] rounded-full" />
          <div className="relative z-10 max-w-3xl mx-auto">
            <h2 className="font-display-xl text-headline-lg mb-6 text-white">Ready to automate your malware analysis?</h2>
            <p className="font-body-lg text-on-surface-variant mb-10 text-lg">
              Join the future of reverse engineering. Deploy Sentinel AI locally and transform 
              your fraud intelligence operations today.
            </p>
            <div className="flex flex-col sm:flex-row justify-center gap-4">
               <button className="px-10 py-5 rounded bg-white text-black font-bold text-lg tracking-tight hover:bg-secondary-fixed transition-all shadow-xl shadow-white/5">
                 Get Started Now
               </button>
               <button className="px-10 py-5 rounded bg-surface-container border border-white/10 text-white font-bold text-lg tracking-tight hover:bg-surface-variant transition-all">
                 View Documentation
               </button>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default LandingPage;
