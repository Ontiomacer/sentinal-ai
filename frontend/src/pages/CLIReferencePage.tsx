import GlassPanel from '../components/ui/GlassPanel'

const commandGroups = [
  {
    title: 'System Readiness',
    commands: [
      'specter status',
      'specter live --case CASE-1234',
      'specter mcp tools',
      'specter ai health',
    ],
  },
  {
    title: 'Case Operations',
    commands: [
      'specter cases list',
      'specter cases create "UPI fraud APK" --investigator "Analyst"',
      'specter cases open CASE-1234',
      'specter triage drives CASE-1234',
    ],
  },
  {
    title: 'Evidence And Reverse Engineering',
    commands: [
      'specter analyze CASE-1234 ./sample.apk',
      'specter ghidra functions CASE-1234 --limit 50',
      'specter ghidra decompile CASE-1234 loginActivity',
      'specter iocs extract CASE-1234',
    ],
  },
  {
    title: 'Reports And MCP Registry',
    commands: [
      'specter reports generate CASE-1234 technical',
      'specter reports list CASE-1234',
      'specter mcp registry --query cybersecurity --limit 20',
      'specter mcp invoke ghidra.diagnostics',
    ],
  },
  {
    title: 'AI Assistance',
    commands: [
      'specter ai suggest --case CASE-1234',
      'specter ai suggest --case CASE-1234 --rules-only',
      'specter neural summary CASE-1234',
      'specter neural attack-map CASE-1234',
    ],
  },
]

const CLIReferencePage = () => {
  return (
    <div className="container-padding fade-in sentinel-mono">
      <section className="max-w-7xl mb-8">
        <div className="mono-oath p-6">
          <div className="font-mono text-[11px] text-on-surface-variant tracking-[0.22em] mb-3">
            SPECTER CLI / FORENSIC OPERATIONS TERMINAL
          </div>
          <h1 className="font-display-xl text-display-xl text-on-surface leading-tight">
            ANALYSIS SHOULD SURVIVE THE BROWSER
          </h1>
          <p className="text-body-md text-on-surface-variant max-w-3xl mt-4">
            The Sentinel web UI and Specter CLI operate against the same FastAPI backend, case vault, Ghidra MCP session, report inventory, and AI endpoints.
          </p>
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-5 gap-gutter max-w-7xl">
        <aside className="lg:col-span-2 space-y-4">
          <GlassPanel className="mono-panel p-5">
            <div className="font-mono text-[10px] tracking-[0.18em] text-on-surface-variant mb-2">
              INSTALL ENTRYPOINTS
            </div>
            <div className="cli-code-block">
              <div><span className="cli-prompt">PS&gt;</span> .\specter.bat status</div>
              <div><span className="cli-prompt">$</span> ./specter status</div>
              <div><span className="cli-prompt">PY&gt;</span> python specter-cli/cli.py status</div>
            </div>
          </GlassPanel>

          <GlassPanel className="mono-panel p-5">
            <div className="font-mono text-[10px] tracking-[0.18em] text-on-surface-variant mb-2">
              DEFAULT BACKEND
            </div>
            <div className="font-mono text-[13px] text-on-surface mb-4">http://localhost:8000</div>
            <div className="border border-white/10 bg-black/40 p-4 text-[13px] leading-6 text-on-surface-variant">
              Set `backend_url` and `active_case` in `specter-cli/config/specter.toml` when running investigations from a dedicated analysis shell.
            </div>
          </GlassPanel>
        </aside>

        <div className="lg:col-span-3 space-y-4">
          {commandGroups.map((group) => (
            <GlassPanel key={group.title} className="mono-panel p-0 overflow-hidden">
              <div className="workstation-panel-header">
                <span className="material-symbols-outlined text-[18px]">terminal</span>
                <span>{group.title}</span>
              </div>
              <div className="p-5 space-y-3">
                {group.commands.map((command) => (
                  <div key={command} className="cli-code-block">
                    <span className="cli-prompt">specter</span>{' '}
                    {command.replace(/^specter\s*/, '').split(' ').map((part, index) => {
                      const className = part.startsWith('--')
                        ? 'cli-flag'
                        : part.startsWith('CASE-') || part.includes('.apk')
                          ? 'cli-value'
                          : ''
                      return (
                        <span key={`${part}-${index}`} className={className}>
                          {part}{index < command.replace(/^specter\s*/, '').split(' ').length - 1 ? ' ' : ''}
                        </span>
                      )
                    })}
                  </div>
                ))}
              </div>
            </GlassPanel>
          ))}
        </div>
      </section>
    </div>
  )
}

export default CLIReferencePage
