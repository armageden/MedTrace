import React from 'react';
import { ComplianceSummary, ForgePanelContext } from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  FileDown,
  GitFork,
  Table,
  Sparkles,
  Zap,
  RefreshCw,
  ScrollText,
} from 'lucide-react';

interface AuditHeaderProps {
  summary: ComplianceSummary;
  panelContext: ForgePanelContext;
  activeView: 'graph' | 'table';
  onToggleView: (view: 'graph' | 'table') => void;
  onSeed: () => void;
  onSyncLive: () => void;
  onOpenAuditLog: () => void;
  onOpenExport: () => void;
  onTestTransition: () => void;
  onAnalyzeBlastRadius: () => void;
  isSeeding: boolean;
  isSyncingLive: boolean;
  isAnalyzingBlastRadius: boolean;
}

export const AuditHeader: React.FC<AuditHeaderProps> = ({
  summary,
  panelContext,
  activeView,
  onToggleView,
  onSeed,
  onSyncLive,
  onOpenAuditLog,
  onOpenExport,
  onTestTransition,
  onAnalyzeBlastRadius,
  isSeeding,
  isSyncingLive,
  isAnalyzingBlastRadius,
}) => {
  const isLive = summary.datasetMode === 'LIVE';
  const contextLabel = panelContext.issueKey
    ? `Jira Issue: ${panelContext.issueKey}`
    : panelContext.contentId
    ? `Confluence Page: ${panelContext.contentId}`
    : panelContext.projectKey
    ? `Jira Project: ${panelContext.projectKey}`
    : panelContext.isConfluence
    ? 'Confluence Global View'
    : 'Jira Project View';

  return (
    <header className="mt-header no-print">
      <div className="mt-header-top">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ background: '#0052cc', borderRadius: 8, padding: 6, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldCheck size={panelContext.isCompactPanel ? 18 : 22} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontSize: panelContext.isCompactPanel ? 15 : 18, fontWeight: 800, color: '#172b4d', letterSpacing: '-0.2px' }}>
              MedTrace{' '}
              {!panelContext.isCompactPanel && (
                <span style={{ fontSize: 13, fontWeight: 500, color: '#505f79' }}>
                  | IEC 62304 & FDA 21 CFR Part 11 Living Traceability Engine
                </span>
              )}
            </div>
            <div style={{ fontSize: 11, color: '#42526e', marginTop: 2, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span>
                Device System: <b>{summary.projectName}</b> • {contextLabel}
              </span>
              {isLive ? (
                <span
                  style={{
                    padding: '1px 7px',
                    borderRadius: 3,
                    background: '#e3fcef',
                    border: '1px solid #abf5d1',
                    color: '#006644',
                    fontWeight: 800,
                    fontSize: 9,
                    letterSpacing: '0.4px',
                  }}
                >
                  LIVE ATLASSIAN DATA
                </span>
              ) : (
                <span
                  style={{
                    padding: '1px 7px',
                    borderRadius: 3,
                    background: '#fff0b3',
                    border: '1px solid #ffe380',
                    color: '#974f0c',
                    fontWeight: 800,
                    fontSize: 9,
                    letterSpacing: '0.4px',
                  }}
                  title="All records are modeled demo data seeded by the app. Use Sync Live Atlassian to ingest real tenant artifacts."
                >
                  DEMO DATASET — MODELED RECORDS
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="mt-actions">
          <div style={{ display: 'flex', background: '#ebecf0', padding: 2, borderRadius: 6 }}>
            <button
              type="button"
              aria-pressed={activeView === 'graph'}
              onClick={() => onToggleView('graph')}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                border: 'none',
                borderRadius: 5,
                background: activeView === 'graph' ? '#ffffff' : 'transparent',
                boxShadow: activeView === 'graph' ? '0 1px 3px rgba(9, 30, 66, 0.12)' : 'none',
                color: activeView === 'graph' ? '#0052cc' : '#42526e',
              }}
            >
              <GitFork size={14} /> Graph
            </button>
            <button
              type="button"
              aria-pressed={activeView === 'table'}
              onClick={() => onToggleView('table')}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                border: 'none',
                borderRadius: 5,
                background: activeView === 'table' ? '#ffffff' : 'transparent',
                boxShadow: activeView === 'table' ? '0 1px 3px rgba(9, 30, 66, 0.12)' : 'none',
                color: activeView === 'table' ? '#0052cc' : '#42526e',
              }}
            >
              <Table size={14} /> Matrix
            </button>
          </div>

          <button
            type="button"
            onClick={onSyncLive}
            disabled={isSyncingLive}
            className="mt-btn"
            style={{
              border: '1.5px solid #00875a',
              background: '#e3fcef',
              color: '#006644',
            }}
          >
            <RefreshCw size={14} />
            {isSyncingLive ? 'Syncing Tenant...' : 'Sync Live Atlassian'}
          </button>

          <button
            type="button"
            onClick={onSeed}
            disabled={isSeeding}
            className="mt-btn"
            style={{
              border: '1.5px solid #0052cc',
              background: '#deebff',
              color: '#0052cc',
            }}
          >
            <Sparkles size={14} />
            {isSeeding ? 'Seeding Demo...' : 'Seed Demo Suite'}
          </button>

          <button
            type="button"
            onClick={onAnalyzeBlastRadius}
            disabled={isAnalyzingBlastRadius}
            className="mt-btn"
            style={{
              border: '1.5px solid #ff991f',
              background: '#fff0b3',
              color: '#974f0c',
            }}
          >
            <Zap size={14} color="#974f0c" />
            {isAnalyzingBlastRadius ? 'Analyzing...' : 'Blast Radius'}
          </button>

          <button
            type="button"
            onClick={onTestTransition}
            className="mt-btn"
            style={{
              border: '1.5px solid #de350b',
              background: '#ffebe6',
              color: '#bf2600',
            }}
          >
            <ShieldAlert size={14} />
            Test Human Gate
          </button>

          <button
            type="button"
            onClick={onOpenAuditLog}
            className="mt-btn"
            style={{
              border: '1px solid #c1c7d0',
              background: '#ffffff',
              color: '#172b4d',
            }}
          >
            <ScrollText size={14} />
            Audit Log ({summary.auditEntryCount ?? 0})
          </button>

          <button
            type="button"
            onClick={onOpenExport}
            className="mt-btn"
            style={{
              border: 'none',
              background: '#0052cc',
              color: '#ffffff',
              boxShadow: '0 2px 4px rgba(0, 82, 204, 0.25)',
            }}
          >
            <FileDown size={14} /> Export Dossier
          </button>
        </div>
      </div>

      {/* Stat Metric Cards */}
      <div className="mt-metrics-grid">
        <div style={cardStyle}>
          <div style={cardLabel}>IEC 62304 VERIFICATION COVERAGE</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
            <span style={{ fontSize: 22, fontWeight: 800, color: summary.verifiedPercentage === 100 ? '#006644' : '#bf2600' }}>
              {summary.verifiedPercentage}%
            </span>
            <span style={{ fontSize: 11, color: '#505f79' }}>
              ({summary.traceLinks.filter((l) => l.complianceState === 'VERIFIED').length}/{summary.totalHazards} Hazards)
            </span>
          </div>
        </div>

        <div style={cardStyle}>
          <div style={cardLabel}>ISO 14971 CLASS C HAZARDS</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
            <span style={{ fontSize: 22, fontWeight: 800, color: '#bf2600' }}>{summary.classCCount}</span>
            <span style={{ fontSize: 11, color: '#505f79' }}>Catastrophic / Severe Risk</span>
          </div>
        </div>

        <div style={{ ...cardStyle, borderLeft: `4px solid ${summary.releaseBlocked ? '#de350b' : '#00875a'}` }}>
          <div style={cardLabel}>JIRA HUMAN RELEASE GATE</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
            {summary.releaseBlocked ? (
              <>
                <ShieldAlert size={18} color="#bf2600" />
                <span style={{ fontSize: 13, fontWeight: 800, color: '#bf2600' }}>RELEASE BLOCKED</span>
              </>
            ) : (
              <>
                <ShieldCheck size={18} color="#006644" />
                <span style={{ fontSize: 13, fontWeight: 800, color: '#006644' }}>AUDIT READY (ZERO GAPS)</span>
              </>
            )}
          </div>
        </div>

        <div style={cardStyle}>
          <div style={cardLabel}>SIGNATURE EVIDENCE STATUS</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
            <span style={{ fontSize: 22, fontWeight: 800, color: summary.signatureDriftCount > 0 ? '#974f0c' : '#006644' }}>
              {summary.signatureDriftCount > 0 ? `${summary.signatureDriftCount} Drifted` : 'All Valid'}
            </span>
            <span style={{ fontSize: 11, color: '#505f79' }}>21 CFR Part 11 SHA-256</span>
          </div>
        </div>
      </div>
    </header>
  );
};

const cardStyle: React.CSSProperties = {
  background: '#fafbfc',
  borderRadius: 6,
  padding: '10px 14px',
  border: '1px solid #ebecf0',
};

const cardLabel: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 800,
  letterSpacing: '0.6px',
  color: '#42526e',
};
