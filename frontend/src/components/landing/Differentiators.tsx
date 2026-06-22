import React from 'react';
import { motion } from 'framer-motion';

const diffs = [
  {
    title: 'AI Reverse Engineering',
    desc: 'Automated decompilation and neural analysis of APK artifacts to extract deep behavioral insights.',
    icon: 'neurology'
  },
  {
    title: 'Function-Level Intelligence',
    desc: 'Each function is analyzed for its specific role in the fraud lifecycle, from exfiltration to persistence.',
    icon: 'terminal'
  },
  {
    title: 'Attack Chain Reconstruction',
    desc: 'Sentinel connects the dots between suspicious activities to visualize the complete execution flow.',
    icon: 'hub'
  },
  {
    title: 'Evidence-Based Risk Scoring',
    desc: 'Deterministic scoring backed by actual code snippets, strings, and network artifacts.',
    icon: 'fact_check'
  },
  {
    title: 'Banking Fraud Detection',
    desc: 'Specialized models for identifying overlays, OTP theft, and accessibility-based account takeover.',
    icon: 'account_balance'
  },
  {
    title: 'Local AI Execution',
    desc: 'Run powerful LLMs on standard CPU hardware (e.g., ThinkPad E490) without sending data to the cloud.',
    icon: 'dns'
  }
];

const Differentiators: React.FC = () => {
  return (
    <section className="py-section-gap px-container-padding-desktop bg-background">
      <div className="max-w-7xl mx-auto">
        <div className="mb-20">
          <h2 className="font-display-xl text-headline-lg mb-4 text-white">Built for Intelligence Operations</h2>
          <p className="font-body-lg text-on-surface-variant max-w-2xl">
            Designed for professional malware researchers and fraud investigators who require precision, 
            privacy, and actionable insights.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {diffs.map((diff, index) => (
            <motion.div
              key={diff.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
              className="p-8 rounded-xl bg-surface-container border border-white/5 hover:border-white/20 transition-all duration-300 group"
            >
              <div className="w-12 h-12 rounded-lg bg-white/5 flex items-center justify-center mb-6 group-hover:bg-purple-500/20 transition-colors">
                <span className="material-symbols-outlined text-2xl text-on-surface group-hover:text-purple-400 transition-colors">
                  {diff.icon}
                </span>
              </div>
              <h3 className="font-title-md text-xl mb-3 text-white group-hover:text-purple-300 transition-colors">{diff.title}</h3>
              <p className="font-body-md text-on-surface-variant leading-relaxed">
                {diff.desc}
              </p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Differentiators;
