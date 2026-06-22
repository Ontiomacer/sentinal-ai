import React from 'react';

const DemoSection: React.FC = () => {
  return (
    <section className="py-section-gap px-container-padding-desktop bg-surface-container-lowest">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-20">
          <h2 className="font-display-xl text-headline-lg mb-4 text-white">Witness the Intelligence</h2>
          <p className="font-body-lg text-on-surface-variant max-w-2xl mx-auto">
            From raw binary to a reconstructed attack narrative. See how Sentinel AI transforms 
            complex reverse engineering into clear intelligence.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          {/* Visual Side */}
          <div className="lg:col-span-7 space-y-6">
            <div className="relative rounded-2xl border border-white/10 bg-surface-container p-2 overflow-hidden shadow-2xl">
              <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-cyan-500/5 to-purple-500/5 pointer-events-none" />
              
              {/* Mock Analysis Card */}
              <div className="bg-surface-container-low rounded-xl border border-white/5 p-6 space-y-6 relative z-10">
                <div className="flex justify-between items-start border-b border-white/10 pb-4">
                  <div className="flex gap-4">
                    <div className="w-12 h-12 rounded bg-white/5 flex items-center justify-center">
                      <span className="material-symbols-outlined text-cyan-400">apk_document</span>
                    </div>
                    <div>
                      <h4 className="font-title-md text-white">TeaBot_v2.apk</h4>
                      <p className="font-label-sm text-[10px] text-on-surface-variant">SHA256: 4f8a...9d2e</p>
                    </div>
                  </div>
                  <div className="px-3 py-1 rounded bg-red-500/20 border border-red-500/30 text-red-400 font-label-sm text-[10px] tracking-widest uppercase">
                    High Risk
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                    <span className="font-label-sm text-xs text-cyan-400 uppercase tracking-widest">Suspicious Function Detected</span>
                  </div>
                  <div className="p-4 bg-surface-container-lowest rounded-lg border border-white/5 font-mono text-[12px] text-on-surface-variant">
                    <div className="text-purple-400">{'void onReceiveSMS(Context ctx, Intent intent) {'}</div>
                    <div className="pl-4">{'Bundle b = intent.getExtras();'}</div>
                    <div className="pl-4">{'if (b != null) {'}</div>
                    <div className="pl-8 text-cyan-400">{'// Intercepting OTP from banking origins'}</div>
                    <div className="pl-8">{'String body = b.getString("body");'}</div>
                    <div className="pl-8">{'if (body.contains("OTP") || body.contains("code")) {'}</div>
                    <div className="pl-12 text-red-400">{'NetworkManager.exfiltrate(body);'}</div>
                    <div className="pl-8">{'}'}</div>
                    <div className="pl-4">{'}'}</div>
                    <div className="text-purple-400">{'}'}</div>
                  </div>
                  <div className="p-4 bg-purple-500/5 border border-purple-500/10 rounded-lg">
                    <div className="flex gap-3">
                      <span className="material-symbols-outlined text-purple-400 text-lg">auto_awesome</span>
                      <p className="font-body-md text-sm text-on-surface leading-relaxed italic">
                        "The AI identified this as an <strong>OTP Interception</strong> chain. 
                        The function monitors incoming SMS messages, filters for verification codes, 
                        and exfiltrates them to a known C2 domain associated with TeaBot."
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Decorative Overlay Elements */}
              <div className="absolute bottom-10 right-10 w-48 p-4 rounded-xl bg-surface-container-high border border-white/20 shadow-2xl backdrop-blur-xl animate-bounce" style={{ animationDuration: '4s' }}>
                <div className="font-label-sm text-[10px] text-on-surface-variant uppercase mb-2">Risk Score</div>
                <div className="text-4xl font-display-xl text-red-500">92/100</div>
                <div className="w-full h-1 bg-white/5 rounded-full mt-3 overflow-hidden">
                  <div className="w-[92%] h-full bg-red-500" />
                </div>
              </div>
            </div>
          </div>

          {/* Text Side */}
          <div className="lg:col-span-5 space-y-8">
            <div className="space-y-4">
               <h3 className="font-display-xl text-3xl text-white">Human-Readable Intelligence from Machine-Level Code</h3>
               <p className="font-body-md text-on-surface-variant leading-relaxed text-lg">
                 Stop manual decompilation marathons. Sentinel AI does the heavy lifting, 
                 presenting you with verified evidence and natural language explanations.
               </p>
            </div>

            <div className="space-y-6">
              {[
                { title: 'Reconstructed Attack Chain', desc: 'Visualizes how the app gains persistence, intercepts data, and communicates with C2.' },
                { title: 'Decompiled Intent', desc: 'Understand the "why" behind obfuscated code via local LLM analysis.' },
                { title: 'Forensic Evidence', desc: 'Direct links to suspicious strings, domains, and API calls within the binary.' }
              ].map((item, i) => (
                <div key={i} className="flex gap-4">
                  <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
                    <span className="material-symbols-outlined text-cyan-400 text-xl">verified</span>
                  </div>
                  <div>
                    <h5 className="font-title-md text-white mb-1">{item.title}</h5>
                    <p className="font-body-md text-sm text-on-surface-variant">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-6">
               <button className="px-8 py-4 rounded bg-cyan-600 text-white font-bold text-sm tracking-tight hover:bg-cyan-500 transition-all shadow-lg shadow-cyan-500/10 flex items-center gap-2 group">
                 Explore Interactive Demo
                 <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">arrow_forward</span>
               </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default DemoSection;
