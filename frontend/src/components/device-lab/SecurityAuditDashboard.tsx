import React, { useState } from 'react';
import { Shield, AlertTriangle, AlertCircle, CheckCircle, Play } from 'lucide-react';

interface AuditResult {
  package: string;
  name: string;
  risk_score: string;
  threat_type: string;
  banking_risk: string;
  severity: string;
  dangerous_permissions: string[];
  permission_count: number;
}

interface SecurityAuditDashboardProps {
  deviceSerial: string | null;
}

export const SecurityAuditDashboard: React.FC<SecurityAuditDashboardProps> = ({
  deviceSerial
}) => {
  const [results, setResults] = useState<AuditResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [totalApps, setTotalApps] = useState(0);
  const [auditedApps, setAuditedApps] = useState(0);

  const startAudit = async () => {
    if (!deviceSerial) {
      alert('No device connected');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      const response = await fetch('/api/v1/device-lab/security/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_serial: deviceSerial })
      });

      const data = await response.json();

      if (data.success) {
        setResults(data.results);
        setTotalApps(data.total_apps);
        setAuditedApps(data.audited_apps);
      }
    } catch (error) {
      console.error('[SecurityAudit] Audit failed:', error);
      alert('Security audit failed');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'text-red-500 bg-red-500/10';
      case 'High': return 'text-orange-500 bg-orange-500/10';
      case 'Medium': return 'text-yellow-500 bg-yellow-500/10';
      case 'Low': return 'text-green-500 bg-green-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'Critical':
      case 'High':
        return <AlertTriangle className="w-4 h-4" />;
      case 'Medium':
        return <AlertCircle className="w-4 h-4" />;
      case 'Low':
        return <CheckCircle className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="h-full flex flex-col bg-gray-900">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-500" />
            Device Security Audit
          </h3>
          <button
            onClick={startAudit}
            disabled={loading || !deviceSerial}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Start Audit
              </>
            )}
          </button>
        </div>

        {results.length > 0 && (
          <div className="mt-4 grid grid-cols-4 gap-4">
            <div className="bg-gray-800 p-3 rounded">
              <div className="text-gray-400 text-sm">Total Apps</div>
              <div className="text-white text-2xl font-bold">{totalApps}</div>
            </div>
            <div className="bg-gray-800 p-3 rounded">
              <div className="text-gray-400 text-sm">Audited</div>
              <div className="text-white text-2xl font-bold">{auditedApps}</div>
            </div>
            <div className="bg-gray-800 p-3 rounded">
              <div className="text-gray-400 text-sm">High Risk</div>
              <div className="text-red-500 text-2xl font-bold">
                {results.filter(r => r.risk_score === 'Critical' || r.risk_score === 'High').length}
              </div>
            </div>
            <div className="bg-gray-800 p-3 rounded">
              <div className="text-gray-400 text-sm">Banking Threats</div>
              <div className="text-orange-500 text-2xl font-bold">
                {results.filter(r => r.banking_risk === 'Yes').length}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Results Table */}
      <div className="flex-1 overflow-y-auto">
        {results.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <Shield className="w-16 h-16 mb-4 opacity-50" />
            <p className="text-lg mb-2">No audit results yet</p>
            <p className="text-sm">Click "Start Audit" to scan all installed applications</p>
          </div>
        )}

        {results.length > 0 && (
          <table className="w-full">
            <thead className="bg-gray-800 sticky top-0">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Application
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Threat Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Banking Risk
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Permissions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {results.map((result, index) => (
                <tr key={index} className="hover:bg-gray-800 transition-colors">
                  <td className="px-4 py-3">
                    <div className="text-white font-medium">{result.name}</div>
                    <div className="text-xs text-gray-400">{result.package}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold ${getRiskColor(result.risk_score)}`}>
                      {getRiskIcon(result.risk_score)}
                      {result.risk_score}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-300">{result.threat_type}</span>
                  </td>
                  <td className="px-4 py-3">
                    {result.banking_risk === 'Yes' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold text-orange-500 bg-orange-500/10">
                        <AlertTriangle className="w-3 h-3" />
                        Yes
                      </span>
                    ) : (
                      <span className="text-sm text-gray-500">No</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-gray-300">
                      {result.dangerous_permissions.length > 0 ? (
                        <details className="cursor-pointer">
                          <summary className="text-red-400">
                            {result.dangerous_permissions.length} dangerous
                          </summary>
                          <ul className="mt-2 text-xs text-gray-400 space-y-1">
                            {result.dangerous_permissions.map((perm, i) => (
                              <li key={i}>• {perm}</li>
                            ))}
                          </ul>
                        </details>
                      ) : (
                        <span className="text-gray-500">Clean</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
