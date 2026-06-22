import React from 'react';
import { motion } from 'framer-motion';
import Logo from './SentinelLogo';

const pipelineSteps = [
  { id: 'upload', label: 'APK Upload', icon: 'upload_file' },
  { id: 'static', label: 'Static Analysis', icon: 'settings_ethernet' },
  { id: 'ghidra', label: 'Ghidra Reverse Engineering', icon: 'memory' },
  { id: 'function', label: 'Function Intelligence', icon: 'psychology' },
  { id: 'attack', label: 'Attack Chain Reconstruction', icon: 'account_tree' },
  { id: 'intent', label: 'Fraud Intent Detection', icon: 'security' },
  { id: 'scoring', label: 'Risk Scoring', icon: 'speed' },
  { id: 'report', label: 'Investigation Report', icon: 'description' },
];

const DeprecatedPipeline: React.FC = () => {
  return (
    <section className="py-section-gap px-container-padding-desktop bg-surface-container-lowest overflow-hidden">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-20">
          <h2 className="font-display-xl text-headline-lg mb-4 text-white">Automated Forensic Pipeline</h2>
          <p className="font-body-lg text-on-surface-variant max-w-2xl mx-auto">
            Our multi-stage analysis engine moves from raw bytes to human-readable fraud intelligence in seconds.
          </p>
        </div>

        <div className="relative">
          {/* Connecting Line */}
          <div className="absolute top-1/2 left-0 w-full h-0.5 bg-gradient-to-r from-purple-500/20 via-cyan-500/50 to-purple-500/20 -translate-y-1/2 hidden lg:block" />

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-8">
            {pipelineSteps.map((step, index) => (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
                className="relative flex flex-col items-center group"
              >
                <div className="w-16 h-16 rounded-lg bg-surface-container border border-white/10 flex items-center justify-center mb-4 relative z-10 group-hover:border-cyan-500/50 group-hover:shadow-[0_0_20px_rgba(6,182,212,0.2)] transition-all duration-300">
                  <span className="material-symbols-outlined text-2xl text-on-surface group-hover:text-cyan-400 transition-colors">
                    {step.icon}
                  </span>
                  
                  {/* Active Indicator Pulse */}
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-500 rounded-full border-2 border-surface-container-lowest animate-pulse" />
                </div>
                
                <span className="font-label-sm text-[10px] text-center text-on-surface-variant uppercase tracking-widest leading-tight group-hover:text-white transition-colors">
                  {step.label}
                </span>

                {/* Vertical line for mobile/tablet */}
                {index < pipelineSteps.length - 1 && (
                  <div className="h-8 w-0.5 bg-white/5 my-2 lg:hidden" />
                )}
              </motion.div>
            ))}
          </div>
        </div>

        {/* Intelligence Callout */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="mt-24 p-1 rounded-2xl bg-gradient-to-r from-purple-500/20 via-cyan-500/20 to-purple-500/20 border border-white/10"
        >
          <div className="bg-surface-container-low rounded-[14px] p-8 md:p-12 flex flex-col md:flex-row items-center gap-8">
            <div className="flex-1">
              <h3 className="font-display-xl text-3xl mb-4 text-white">Not just a scanner. An Analyst.</h3>
              <p className="font-body-md text-on-surface-variant mb-6">
                While traditional tools stop at signature matching, Sentinel AI uses local Generative AI to 
                understand the <strong>intent</strong> behind the code. It identifies why a function is 
                requesting SMS permissions and how that fits into a larger banking fraud campaign.
              </p>
              <ul className="space-y-3">
                {[
                  'Reconstructs multi-stage attack chains from artifacts',
                  'Maps technical findings to MITRE ATT&CK® techniques',
                  'Differentiates benign SDK behavior from malicious overlays',
                  'Executes locally for maximum data privacy'
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-sm text-on-surface">
                    <span className="material-symbols-outlined text-cyan-400 text-lg">check_circle</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="w-full md:w-1/3 aspect-square bg-gradient-to-br from-white/5 to-white/0 rounded-xl border border-white/10 flex items-center justify-center relative overflow-hidden group">
               <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(6,182,212,0.1)_0%,transparent_70%)]" />
               <Logo className="w-32 h-32 group-hover:scale-110 transition-transform duration-500" />
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default DeprecatedPipeline;
