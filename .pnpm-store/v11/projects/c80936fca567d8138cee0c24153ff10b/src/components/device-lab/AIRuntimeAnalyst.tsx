/**
 * AI Runtime Analyst - Qwen-Powered Real-Time Analysis
 * Explains runtime behavior with evidence-based findings
 */

import React, { useState } from 'react';
import { Brain, AlertTriangle, Shield, CheckCircle, Loader } from 'lucide-react';

interface AIRuntimeAnalystProps {
  deviceSerial: string | null;
  runtimeContext: {
    activities?: any[];
    services?: any[];
    permissions?: string[];
    processes?: any[];
    network?: any[];
  };
}

interface AIAnalysis {
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  banking_threat: 'YES' | 'NO';
  key_findings: string[];
  suspicious_behaviors: string[];
  recommendations: string[];
  raw_analysis: string;
}

export const AIRuntimeAnalyst: React.FC<AIRuntimeAnalystProps> = ({
  deviceSerial,
  runtimeContext
}) => {
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const runAnalysis = async () => {
    if (!deviceSerial) {
      alert('No device connected');
      return;
    }

    setAnalyzing(true);

    try {
      const response = await fetch('/api/v1/device-lab/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: deviceSerial,
          context: runtimeContext
        })
      });

      const data = await response.json();

      if (data.success) {
        setAnalysis(data.analysis);
      }
    } catch (error) {
      console.error('[AIRuntimeAnalyst] Analysis failed:', error);
      alert('AI analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10';
      case 'LOW': return 'text-green-500 bg-green-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return <AlertTriangle className="w-5 h-5" />;
      case 'MEDIUM':
        return <Shield className="w-5 h-5" />;
      case 'LOW':
        return <CheckCircle className="w-5 h-5" />;
      default:
        return <Brain className="w-5 h-5" />;
    }
  };

  return (
    <div className="h-full flex flex-col bg-gray-900">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-500" />
            AI Runtime Analyst
          </h3>
          <button
            onClick={runAnalysis}
            disabled={analyzing || !deviceSerial}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {analyzing ? (
              <>
                <Loader className="w-4 h-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Brain className="w-4 h-4" />
                Analyze Runtime
              </>
            )}
          </button>
        </div>
        <p className="text-sm text-gray-400 mt-2">
          Qwen-powered real-time analysis of device runtime behavior
        </p>
      </div>

      {/* Analysis Results */}
      <div className="flex-1 overflow-y-auto p-4">
        {!analysis && !analyzing && (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <Brain className="w-16 h-16 mb-4 opacity-50" />
            <p className="text-lg mb-2">No analysis yet</p>
            <p className="text-sm text-center">
              Click "Analyze Runtime" to get AI-powered insights<br />
              about device behavior and security threats
            </p>
          </div>
        )}

        {analysis && (
          <div className="space-y-4">
            {/* Threat Level */}
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400 uppercase tracking-wide">Threat Level</span>
                <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded font-semibold ${getThreatColor(analysis.threat_level)}`}>
                  {getThreatIcon(analysis.threat_level)}
                  {analysis.threat_level}
                </span>
              </div>
              
              {analysis.banking_threat === 'YES' && (
                <div className="mt-3 flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-sm">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="font-semibold">Banking Malware Threat Detected</span>
                </div>
              )}
            </div>

            {/* Key Findings */}
            {analysis.key_findings && analysis.key_findings.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                  Key Findings
                </h4>
                <ul className="space-y-2">
                  {analysis.key_findings.map((finding, index) => (
                    <li key={index} className="text-sm text-gray-300 flex items-start gap-2">
                      <span className="text-orange-500 mt-0.5">•</span>
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Suspicious Behaviors */}
            {analysis.suspicious_behaviors && analysis.suspicious_behaviors.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-yellow-500" />
                  Suspicious Behaviors
                </h4>
                <ul className="space-y-2">
                  {analysis.suspicious_behaviors.map((behavior, index) => (
                    <li key={index} className="text-sm text-gray-300 flex items-start gap-2">
                      <span className="text-yellow-500 mt-0.5">•</span>
                      <span>{behavior}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Recommendations */}
            {analysis.recommendations && analysis.recommendations.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-4">
                <h4 className="text-white font-semibold mb-3 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  Recommendations
                </h4>
                <ul className="space-y-2">
                  {analysis.recommendations.map((rec, index) => (
                    <li key={index} className="text-sm text-gray-300 flex items-start gap-2">
                      <span className="text-green-500 mt-0.5">•</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Raw Analysis */}
            {analysis.raw_analysis && (
              <details className="bg-gray-800 rounded-lg p-4">
                <summary className="text-white font-semibold cursor-pointer hover:text-purple-400 transition-colors">
                  Full AI Analysis
                </summary>
                <div className="mt-3 text-sm text-gray-300 whitespace-pre-wrap font-mono">
                  {analysis.raw_analysis}
                </div>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
