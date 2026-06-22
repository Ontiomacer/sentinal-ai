import React from 'react';
import { motion } from 'framer-motion';
import Logo from './SentinelLogo';

const Hero: React.FC = () => {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center pt-20 px-container-padding-desktop overflow-hidden bg-background">
      {/* Background Decorative Elements */}
      <div className="absolute inset-0 z-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-600/10 rounded-full blur-[128px] animate-pulse-slow" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyan-600/10 rounded-full blur-[128px] animate-pulse-slow" style={{ animationDelay: '1s' }} />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        className="relative z-10 flex flex-col items-center text-center max-w-5xl"
      >
        <div className="mb-8">
          <Logo className="w-24 h-24" />
        </div>
        
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 mb-6 backdrop-blur-md"
        >
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="font-label-sm text-xs tracking-widest text-cyan-400 uppercase">
            Generative AI-Powered APK Reverse Engineering
          </span>
        </motion.div>

        <h1 className="font-display-xl text-headline-lg md:text-[80px] leading-[1.1] mb-6 tracking-tight text-white">
          Reverse Engineering the <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-white to-cyan-400">
            Future of Banking Security
          </span>
        </h1>

        <p className="font-body-lg text-on-surface-variant max-w-2xl mb-10 text-lg leading-relaxed">
          Sentinel AI automatically dissects Android applications, 
          identifies malicious behavior, reconstructs attack chains, 
          and generates evidence-backed fraud intelligence.
        </p>

        <div className="flex flex-col sm:flex-row gap-4">
          <button className="px-8 py-4 rounded bg-white text-black font-bold text-sm tracking-tight hover:bg-secondary-fixed transition-all shadow-lg shadow-white/10 group flex items-center gap-2">
            Start Investigation
            <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">arrow_forward</span>
          </button>
          <button className="px-8 py-4 rounded bg-surface-container border border-white/10 text-white font-bold text-sm tracking-tight hover:bg-surface-variant transition-all backdrop-blur-sm flex items-center gap-2">
            <span className="material-symbols-outlined text-sm">upload_file</span>
            Upload APK
          </button>
        </div>

        {/* Dashboard Preview or Abstract Visual */}
        <motion.div
          initial={{ opacity: 0, y: 100 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 1 }}
          className="mt-20 relative w-full max-w-6xl"
        >
          <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-transparent z-10" />
          <div className="rounded-xl border border-white/10 bg-surface-container/50 backdrop-blur-sm overflow-hidden shadow-2xl">
            <div className="h-8 border-b border-white/10 flex items-center px-4 gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500/20" />
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/20" />
              <div className="w-2.5 h-2.5 rounded-full bg-green-500/20" />
              <div className="ml-4 h-4 w-48 bg-white/5 rounded" />
            </div>
            <div className="aspect-video bg-surface-container-low flex items-center justify-center overflow-hidden">
               {/* Simplified Mock UI */}
               <div className="grid grid-cols-12 gap-4 w-full h-full p-6">
                 <div className="col-span-3 space-y-4">
                   <div className="h-32 bg-white/5 rounded border border-white/5 animate-pulse" />
                   <div className="h-48 bg-white/5 rounded border border-white/5 animate-pulse" style={{ animationDelay: '0.2s' }} />
                 </div>
                 <div className="col-span-6">
                   <div className="h-full bg-white/5 rounded border border-white/5 flex items-center justify-center relative overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-purple-500/10 to-cyan-500/10" />
                      <div className="relative z-10 text-center space-y-2">
                        <div className="w-16 h-16 rounded-full bg-white/10 mx-auto flex items-center justify-center border border-white/10">
                          <span className="material-symbols-outlined text-3xl text-cyan-400">psychology</span>
                        </div>
                        <div className="font-label-sm text-[10px] text-cyan-400 tracking-widest uppercase">Analyzing Behavioral Graph...</div>
                      </div>
                   </div>
                 </div>
                 <div className="col-span-3 space-y-4">
                   <div className="h-64 bg-white/5 rounded border border-white/5 animate-pulse" style={{ animationDelay: '0.4s' }} />
                   <div className="h-16 bg-white/5 rounded border border-white/5 animate-pulse" style={{ animationDelay: '0.6s' }} />
                 </div>
               </div>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </section>
  );
};

export default Hero;
