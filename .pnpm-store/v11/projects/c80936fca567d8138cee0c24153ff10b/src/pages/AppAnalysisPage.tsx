import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Brain,
  CheckCircle,
  Code,
  FileCode2,
  Fingerprint,
  Loader2,
  Network,
  Package,
  Shield,
  XCircle
} from 'lucide-react';

type PipelineStep = {
  key: string;
  label: string;
  status: 'complete' | 'running' | 'pending' | string;
};

type AnalysisResult = Record<string, any>;

const asArray = <T,>(value: unknown): T[] => Array.isArray(value) ? value as T[] : [];
const asObject = (value: unknown): Record<string, any> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {};
const text = (value: unknown, empty = 'Data unavailable') => {
  if (value === null || value === undefined || value === '') return empty;
  return String(value);
};

const severityClass = (value?: string) => {
  const upper = (value || '').toUpperCase();
  if (['MALICIOUS', 'CRITICAL', 'HIGH_RISK', 'HIGH'].includes(upper)) return 'border-red-500/45 bg-red-500/10 text-red-200';
  if (['SUSPICIOUS', 'MEDIUM', 'WARNING'].includes(upper)) return 'border-yellow-400/45 bg-yellow-400/10 text-yellow-100';
  if (['SAFE', 'BENIGN', 'LOW'].includes(upper)) return 'border-green-400/45 bg-green-400/10 text-green-100';
  return 'border-white/10 bg-white/[0.03] text-white/65';
};

const dotClass = (value?: string) => {
  const upper = (value || '').toUpperCase();
  if (['MALICIOUS', 'CRITICAL', 'HIGH_RISK', 'HIGH'].includes(upper)) return 'bg-red-400';
  if (['SUSPICIOUS', 'MEDIUM', 'WARNING'].includes(upper)) return 'bg-yellow-300';
  if (['SAFE', 'BENIGN', 'LOW'].includes(upper)) return 'bg-green-400';
  return 'bg-white/35';
};

const statusMarker = (status: string) => {
  if (status === 'complete') return 'OK';
  if (status === 'running') return 'RUN';
  return 'WAIT';
};

const DataList = ({ items, render }: { items: any[]; render?: (item: any, index: number) => React.ReactNode }) => {
  if (!items.length) return <p className="font-mono text-sm text-white/35">Data unavailable</p>;
  return (
    <div className="space-y-2">
      {items.slice(0, 120).map((item, index) => (
        <div key={`${JSON.stringify(item).slice(0, 80)}-${index}`} className="border border-white/10 bg-white/[0.025] p-3">
          {render ? render(item, index) : <pre className="overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-white/70">{JSON.stringify(item, null, 2)}</pre>}
        </div>
      ))}
    </div>
  );
};

const Metric = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div className="border border-white/10 bg-white/[0.025] p-3">
    <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.18em] text-white/35">{label}</div>
    <div className="font-mono text-sm text-white">{value}</div>
  </div>
);

const Section = ({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) => (
  <section className="border-t border-white/10 py-8 first:border-t-0 first:pt-0">
    <div className="mb-4 flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center border border-white/10 bg-white/[0.03]">
        <Icon className="h-4 w-4" />
      </div>
      <h2 className="text-sm font-semibold uppercase tracking-[0.2em]">{title}</h2>
    </div>
    {children}
  </section>
);

const AppAnalysisPage: React.FC = () => {
  const { analysisId } = useParams<{ analysisId?: string }>();
  const [searchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();

  const packageName = searchParams.get('package');
  const serial = searchParams.get('serial');
  const state = (location.state || {}) as any;

  const [analysis, setAnalysis] = useState<AnalysisResult | null>(state.result || null);
  const [quickScan, setQuickScan] = useState<any>(state.quickScan || null);
  const [progress, setProgress] = useState(analysis ? 100 : 0);
  const [currentStep, setCurrentStep] = useState(analysis ? 'Analysis complete' : 'Preparing analysis');
  const [pipeline, setPipeline] = useState<PipelineStep[]>([]);
  const [error, setError] = useState<string | null>(null);
  const startedRef = useRef<string | null>(null);

  useEffect(() => {
    const key = analysisId || `${packageName || ''}:${serial || ''}`;
    if (!key || startedRef.current === key) return;
    startedRef.current = key;

    if (analysisId) {
      pollAnalysisStatus(analysisId);
      return;
    }

    if (packageName && serial) {
      startQuickScan(packageName, serial);
      return;
    }

    setError('Missing analysis_id or package/device serial');
  }, [analysisId, packageName, serial]);

  const startQuickScan = async (pkg: string, deviceSerial: string) => {
    setError(null);
    setCurrentStep('Extracting APK from device');
    setProgress(5);
    try {
      const response = await fetch(`/api/v1/app-analysis/quick-scan?package_name=${encodeURIComponent(pkg)}&serial=${encodeURIComponent(deviceSerial)}`, {
        method: 'POST'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data?.detail || `APK extraction failed (${response.status})`);
      }
      if (!data.analysis_id) {
        throw new Error('APK extraction succeeded but analysis_id was not returned');
      }
      setQuickScan(data.quick_scan || null);
      setPipeline(data.pipeline || []);
      navigate(`/app-analysis/${encodeURIComponent(data.analysis_id)}`, {
        replace: true,
        state: { quickScan: data.quick_scan, sha256: data.sha256, packageName: pkg, serial: deviceSerial }
      });
      if (data.status === 'completed' && data.result) {
        setAnalysis(data.result);
        setProgress(100);
        setCurrentStep('Automated Security Assessment');
      }
    } catch (err: any) {
      setError(err?.message || 'APK extraction failed');
    }
  };

  const pollAnalysisStatus = async (id: string) => {
    let active = true;
    let attempts = 0;
    const maxAttempts = 180;

    const poll = async () => {
      if (!active) return;
      try {
        const response = await fetch(`/api/v1/app-analysis/status/${encodeURIComponent(id)}`);
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data?.detail || `Analysis status failed (${response.status})`);
        }

        setProgress(data.progress ?? 0);
        setCurrentStep(data.current_step || 'Analyzing APK');
        setPipeline(data.pipeline || []);

        if (data.status === 'failed') {
          throw new Error(data.error || data.error_message || 'Analysis failed');
        }

        if (data.status === 'completed' && data.result) {
          setAnalysis(data.result);
          setProgress(100);
          setCurrentStep(data.current_step || 'Automated Security Assessment');
          return;
        }

        attempts += 1;
        if (attempts < maxAttempts) window.setTimeout(poll, data.status === 'completed' ? 2500 : 1500);
        else throw new Error('Analysis timed out while waiting for backend status');
      } catch (err: any) {
        setError(err?.message || 'Analysis status failed');
      }
    };

    poll();
    return () => {
      active = false;
    };
  };

  const normalized = useMemo(() => {
    const result = analysis || {};
    const summary = asObject(result.executive_summary);
    const apk = asObject(result.apk_analysis || result);
    const manifest = asObject(result.manifest_intelligence);
    const dex = asObject(result.dex_intelligence);
    const code = asObject(result.code_intelligence);
    const network = asObject(result.network_intelligence);
    const cert = summary.certificate || asArray(apk.certificates)[0] || asArray(result.certificates)[0] || {};
    const risk = asObject(result.risk_assessment_internal || result.threat_assessment || result.risk_assessment);
    const ai = asObject(result.security_assessment || result.automated_security_assessment || result.ai_assessment);
    const attackChain = asObject(result.attack_chain);
    const security = asObject(result.security_weaknesses);
    const obfuscation = asObject(result.obfuscation_analysis);
    const banking = asObject(result.banking_trojan_detection);
    const permissions = asArray(summary.permissions || result.permission_intelligence?.permissions || apk.permissions);

    return {
      result,
      summary,
      apk,
      manifest,
      dex,
      code,
      network,
      cert: asObject(cert),
      risk,
      ai,
      attackChain,
      security,
      obfuscation,
      banking,
      permissions,
      activities: asArray(manifest.activities || apk.activities),
      services: asArray(manifest.services || apk.services),
      receivers: asArray(manifest.receivers || apk.receivers),
      providers: asArray(manifest.providers || apk.providers),
      components: [
        ...asArray(manifest.activities || apk.activities).map((item) => ({ kind: 'Activity', ...asObject(item), value: item })),
        ...asArray(manifest.services || apk.services).map((item) => ({ kind: 'Service', ...asObject(item), value: item })),
        ...asArray(manifest.receivers || apk.receivers).map((item) => ({ kind: 'Receiver', ...asObject(item), value: item })),
        ...asArray(manifest.providers || apk.providers).map((item) => ({ kind: 'Provider', ...asObject(item), value: item }))
      ],
      suspiciousApis: asArray(code.suspicious_functions || apk.suspicious_functions),
      apiUsage: asArray(code.api_usage || apk.api_usage),
      urls: asArray(network.urls || apk.urls),
      domains: asArray(network.domains || apk.domains),
      ips: asArray(network.ip_addresses || apk.network_artifacts?.ip_addresses),
      strings: asArray(apk.strings),
      nativeLibraries: asArray(dex.native_libraries || apk.native_libraries || apk.libraries)
    };
  }, [analysis]);

  const summary = normalized.summary;
  const ai = normalized.ai;
  const riskScore = summary.risk_score ?? normalized.risk.overall_score ?? normalized.risk.risk_score;
  const threatLevel = summary.threat_level ?? normalized.risk.threat_level ?? normalized.risk.severity;
  const appName = summary.name || normalized.apk.app_name || quickScan?.app_name || state.packageName || packageName || 'APK Investigation';
  const packageLabel = summary.package || normalized.result.package || normalized.apk.package_name || quickScan?.package_name || state.packageName || packageName;
  const aiVerdict = ai.status === 'unavailable'
    ? `Automated security assessment unavailable${ai._ai_error_message ? `: ${ai._ai_error_message}` : ''}`
    : text(ai.verdict, 'Data unavailable');

  if (error && !analysis) {
    return (
      <div className="min-h-[calc(100vh-7.5rem)] bg-black px-6 py-10 text-white">
        <button onClick={() => navigate('/device-lab')} className="mb-8 flex items-center gap-2 text-sm text-white/55 hover:text-white">
          <ArrowLeft className="h-4 w-4" />
          Back to Device Lab
        </button>
        <div className="mx-auto max-w-2xl border border-red-400/35 bg-red-500/10 p-6">
          <XCircle className="mb-4 h-10 w-10 text-red-300" />
          <h1 className="mb-2 text-xl font-semibold">APK extraction or analysis failed</h1>
          <p className="font-mono text-sm text-red-100">{error}</p>
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="min-h-[calc(100vh-7.5rem)] bg-black px-6 py-10 text-white">
        <div className="mx-auto max-w-4xl">
          <button onClick={() => navigate('/device-lab')} className="mb-8 flex items-center gap-2 text-sm text-white/55 hover:text-white">
            <ArrowLeft className="h-4 w-4" />
            Back to Device Lab
          </button>
          <div className="border border-white/10 bg-white/[0.025] p-6">
            <div className="mb-6 flex items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-white/75" />
              <div>
                <h1 className="text-xl font-semibold uppercase tracking-[0.14em]">Building APK Investigation</h1>
                <p className="mt-1 font-mono text-sm text-white/45">{currentStep}</p>
              </div>
            </div>
            <div className="mb-5 h-2 bg-white/10">
              <div className="h-2 bg-white transition-all" style={{ width: `${Math.max(2, Math.min(100, progress))}%` }} />
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              {pipeline.map((step) => (
                <div key={step.key} className="flex items-center justify-between border border-white/10 bg-black px-3 py-2 font-mono text-xs uppercase tracking-[0.12em]">
                  <span className="text-white/65">{step.label}</span>
                  <span className={step.status === 'complete' ? 'text-green-300' : step.status === 'running' ? 'text-yellow-200' : 'text-white/30'}>
                    {statusMarker(step.status)}
                  </span>
                </div>
              ))}
            </div>
            {quickScan && (
              <div className="mt-6 border border-white/10 bg-black p-4">
                <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-white/35">Quick scan extracted</div>
                <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-white/60">{JSON.stringify(quickScan, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[calc(100vh-7.5rem)] bg-black text-white">
      <header className="border-b border-white/10 bg-black px-6 py-5">
        <div className="mx-auto max-w-[1500px]">
          <button onClick={() => navigate('/device-lab')} className="mb-5 flex items-center gap-2 text-sm text-white/55 hover:text-white">
            <ArrowLeft className="h-4 w-4" />
            Device Lab
          </button>
          <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
            <div>
              <div className="mb-3 flex flex-wrap items-center gap-3">
                <span className={`inline-flex items-center gap-2 border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.16em] ${severityClass(threatLevel)}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${dotClass(threatLevel)}`} />
                  {text(threatLevel, 'Unclassified')}
                </span>
                {analysis.performance?.cache_hit && <span className="border border-green-400/30 px-3 py-1.5 font-mono text-xs uppercase tracking-[0.14em] text-green-200">SHA cache hit</span>}
              </div>
              <h1 className="text-3xl font-semibold tracking-tight">{appName}</h1>
              <p className="mt-2 break-all font-mono text-sm text-white/50">{text(packageLabel)}</p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Metric label="Risk score" value={text(riskScore)} />
              <Metric label="Assessment" value={ai.status === 'available' ? text(ai.threat_level || ai.severity, 'Ready') : 'Unavailable'} />
              <Metric label="Version" value={text(summary.version_name || normalized.apk.version_name)} />
              <Metric label="SHA256" value={<span className="break-all text-[11px]">{text(summary.sha256 || analysis.sha256)}</span>} />
            </div>
          </div>

          <div className="mt-5 grid gap-2 md:grid-cols-4">
            <Metric label="Certificate" value={text(normalized.cert.subject || normalized.cert.issuer || summary.developer)} />
            <Metric label="Permissions" value={normalized.permissions.length} />
            <Metric label="Components" value={normalized.components.length} />
            <Metric label="Analysis status" value={currentStep} />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-6 py-8">
        <Section title="Executive Summary" icon={Shield}>
          <div className="grid gap-4 xl:grid-cols-3">
            <Metric label="Package" value={<span className="break-all">{text(packageLabel)}</span>} />
            <Metric label="Main activity" value={text(summary.main_activity || normalized.apk.main_activity)} />
            <Metric label="Local APK" value={analysis.apk_storage?.device_required === false ? 'Device independent' : text(analysis.apk_storage?.local_path)} />
            <Metric label="Target SDK" value={text(summary.target_sdk || normalized.apk.target_sdk_version)} />
            <Metric label="Min SDK" value={text(summary.min_sdk || normalized.apk.min_sdk_version)} />
            <Metric label="Attack surface" value={`${normalized.permissions.length} permissions / ${normalized.components.length} components`} />
          </div>
          <div className="mt-4 border border-white/10 bg-white/[0.025] p-4">
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">Evidence findings</h3>
            <DataList items={asArray(normalized.risk.risk_factors || normalized.risk.findings || normalized.ai.key_findings)} render={(item) => <p className="font-mono text-sm text-white/70">{text(item)}</p>} />
          </div>
        </Section>

        <Section title="Risk Score" icon={AlertTriangle}>
          <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
            <div className={`border p-5 ${severityClass(threatLevel)}`}>
              <div className="font-mono text-[10px] uppercase tracking-[0.18em] opacity-70">Static verdict</div>
              <div className="mt-3 text-3xl font-semibold">{text(threatLevel, 'Unclassified')}</div>
              <div className="mt-2 font-mono text-sm">Risk score: {text(riskScore)}</div>
              <div className="mt-1 font-mono text-sm">Confidence: {text(summary.malicious_confidence ?? normalized.risk.malicious_confidence)}%</div>
            </div>
            <DataList items={asArray(normalized.risk.risk_factors || normalized.risk.findings)} render={(item) => <p className="font-mono text-sm text-white/70">{text(item)}</p>} />
          </div>
        </Section>

        <Section title="Automated Security Assessment" icon={Brain}>
          <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
            <div className="border border-white/10 bg-white/[0.025] p-5">
              <div className="mb-3 flex items-center gap-2">
                {ai.status === 'available' ? <CheckCircle className="h-5 w-5 text-green-300" /> : <AlertTriangle className="h-5 w-5 text-red-200" />}
                <h3 className="text-sm font-semibold uppercase tracking-[0.16em]">Sentinel Assessment Engine</h3>
              </div>
              <p className="whitespace-pre-wrap text-sm leading-6 text-white/75">{aiVerdict}</p>
              {ai._ai_error_type && <p className="mt-3 font-mono text-xs text-red-200">{ai._ai_error_type}: {text(ai._ai_error_message)}</p>}
            </div>
            <div className="space-y-3">
              <Metric label="Engine" value={text(ai.engine || ai.model, 'Sentinel Assessment Engine')} />
              <Metric label="Status" value={text(ai.status)} />
              <Metric label="Confidence" value={ai.malicious_confidence !== null && ai.malicious_confidence !== undefined ? `${ai.malicious_confidence}%` : 'Data unavailable'} />
              <Metric label="Provider" value={text(ai.provider, 'rule_based')} />
            </div>
          </div>
        </Section>

        <Section title="Attack Chain" icon={FileCode2}>
          <div className="space-y-3">
            {asArray(normalized.attackChain.stages).length ? (
              asArray(normalized.attackChain.stages).map((stage: any, index: number) => (
                <div key={`${stage.stage || index}`} className="grid gap-3 md:grid-cols-[220px_1fr]">
                  <div className={`border p-3 ${severityClass(stage.risk)}`}>
                    <div className="font-mono text-[10px] uppercase tracking-[0.18em] opacity-70">Step {index + 1}</div>
                    <div className="mt-1 font-semibold">{text(stage.stage)}</div>
                  </div>
                  <div className="border border-white/10 bg-white/[0.025] p-3">
                    <p className="text-sm text-white/75">{text(stage.description)}</p>
                    <div className="mt-2 space-y-1">
                      {asArray(stage.evidence).filter(Boolean).map((ev, evIndex) => (
                        <p key={evIndex} className="font-mono text-xs text-white/45">{text(ev)}</p>
                      ))}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <p className="font-mono text-sm text-white/35">No attack chain reconstructed from extracted evidence.</p>
            )}
          </div>
        </Section>

        <Section title="Permissions" icon={Shield}>
          <DataList items={normalized.permissions} render={(item) => (
            <p className="font-mono text-sm text-white/70">
              {text(item?.name || item)}
              <span className="text-white/30"> {text(item?.category, '')}</span>
            </p>
          )} />
        </Section>

        <Section title="Components" icon={Package}>
          <div className="mb-4 grid gap-3 md:grid-cols-4">
            <Metric label="Activities" value={normalized.activities.length} />
            <Metric label="Services" value={normalized.services.length} />
            <Metric label="Receivers" value={normalized.receivers.length} />
            <Metric label="Providers" value={normalized.providers.length} />
          </div>
          <DataList items={normalized.components} render={(item) => <p className="font-mono text-sm text-white/70">{item.kind}: {text(item.name || item.value)}</p>} />
        </Section>

        <Section title="Strings" icon={FileCode2}>
          <DataList items={normalized.strings} render={(item) => <p className="break-all font-mono text-sm text-white/70">{text(item)}</p>} />
        </Section>

        <Section title="Network" icon={Network}>
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <Metric label="Domains" value={normalized.domains.length} />
            <Metric label="URLs" value={normalized.urls.length} />
            <Metric label="IPs" value={normalized.ips.length} />
          </div>
          <div className="grid gap-4 xl:grid-cols-3">
            <div><h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">Domains</h3><DataList items={normalized.domains} render={(item) => <p className="font-mono text-sm text-white/70">{text(item)}</p>} /></div>
            <div><h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">URLs</h3><DataList items={normalized.urls} render={(item) => <p className="break-all font-mono text-sm text-white/70">{text(item)}</p>} /></div>
            <div><h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">IPs</h3><DataList items={normalized.ips} render={(item) => <p className="font-mono text-sm text-white/70">{text(item)}</p>} /></div>
          </div>
        </Section>

        <Section title="Certificates" icon={Fingerprint}>
          <div className="grid gap-3 md:grid-cols-2">
            <Metric label="Issuer" value={text(normalized.cert.issuer)} />
            <Metric label="Subject" value={text(normalized.cert.subject || summary.developer)} />
            <Metric label="Signature algorithm" value={text(normalized.cert.signature_algorithm || normalized.cert.algorithm)} />
            <Metric label="Expiry" value={text(normalized.cert.not_after || normalized.cert.expiry || normalized.cert.valid_until)} />
            <Metric label="SHA256 fingerprint" value={<span className="break-all">{text(normalized.cert.sha256 || normalized.cert.fingerprint_sha256)}</span>} />
            <Metric label="Signed" value={summary.is_signed === true ? 'Yes' : summary.is_signed === false ? 'No' : 'Data unavailable'} />
          </div>
        </Section>

        <Section title="Code Intelligence" icon={Code}>
          <div className="mb-4 grid gap-3 md:grid-cols-4">
            <Metric label="Suspicious APIs" value={normalized.suspiciousApis.length} />
            <Metric label="Reflection" value={normalized.code.reflection_usage || normalized.dex.has_reflection ? 'Detected' : 'Data unavailable'} />
            <Metric label="Dynamic loading" value={normalized.code.dynamic_code_execution || normalized.dex.has_dynamic_loading ? 'Detected' : 'Data unavailable'} />
            <Metric label="Native libraries" value={normalized.nativeLibraries.length || 'Data unavailable'} />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <div>
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">Suspicious functions and APIs</h3>
              <DataList items={[...normalized.suspiciousApis, ...normalized.apiUsage]} />
            </div>
            <div>
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em]">Obfuscation and secrets</h3>
              <div className="space-y-3">
                <Metric label="Obfuscation score" value={text(normalized.obfuscation.obfuscation_score)} />
                <DataList items={[
                  ...asArray(normalized.obfuscation.techniques_detected),
                  ...asArray(normalized.security.api_keys),
                  ...asArray(normalized.security.tokens),
                  ...asArray(normalized.security.passwords)
                ]} render={(item) => <p className="font-mono text-sm text-white/70">{text(item)}</p>} />
              </div>
            </div>
          </div>
        </Section>
      </main>
    </div>
  );
};

export default AppAnalysisPage;
