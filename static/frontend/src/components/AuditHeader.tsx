import React, { useEffect, useRef, useState } from 'react';
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

export interface AuditHeaderProps {
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
  isMutating?: boolean;
  isBusy?: boolean;
  isCompactPanel?: boolean;
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
  isMutating = false,
  isBusy = false,
  isCompactPanel,
}) => {
  const [isActionsMenuOpen, setIsActionsMenuOpen] = useState(false);
  const actionsMenuContainerRef = useRef<HTMLDivElement>(null);
  const actionsTriggerRef = useRef<HTMLButtonElement>(null);
  const actionsMenuRef = useRef<HTMLDivElement>(null);

  const compact = isCompactPanel ?? panelContext.isCompactPanel;
  const mutationBusy = Boolean(isBusy || isMutating || isSeeding || isSyncingLive);
  const isLive = summary.datasetMode === 'LIVE';
  const isUninitialized = summary.initialized === false || summary.totalHazards === 0;
  const verifiedCount = summary.traceLinks.filter((l) => l.complianceState === 'VERIFIED').length;
  const invalidSigCount = summary.traceLinks.filter((l) => !l.signature?.isValid).length;
  const driftCount = summary.signatureDriftCount;
  const unsignedOrInvalidCount = Math.max(0, invalidSigCount - driftCount);
  const blockingCount = summary.blockingReasons.length;
  const gateBlocked = isUninitialized || summary.releaseBlocked;

  useEffect(() => {
    if (!compact && isActionsMenuOpen) {
      setIsActionsMenuOpen(false);
    }
  }, [compact, isActionsMenuOpen]);

  useEffect(() => {
    if (!isActionsMenuOpen) {
      return;
    }

    const menuEl = actionsMenuRef.current;
    if (menuEl) {
      const firstEnabled = menuEl.querySelector<HTMLButtonElement>('[role="menuitem"]:not(:disabled)');
      firstEnabled?.focus();
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        setIsActionsMenuOpen(false);
        actionsTriggerRef.current?.focus();
        return;
      }

      if (!menuEl || !menuEl.contains(document.activeElement)) {
        return;
      }

      const items = Array.from(
        menuEl.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)')
      );
      if (items.length === 0) return;

      const currentIndex = items.indexOf(document.activeElement as HTMLButtonElement);
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        const nextIndex = currentIndex >= 0 ? (currentIndex + 1) % items.length : 0;
        items[nextIndex].focus();
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        const prevIndex = currentIndex >= 0 ? (currentIndex - 1 + items.length) % items.length : items.length - 1;
        items[prevIndex].focus();
      } else if (event.key === 'Home') {
        event.preventDefault();
        items[0].focus();
      } else if (event.key === 'End') {
        event.preventDefault();
        items[items.length - 1].focus();
      }
    };

    const handlePointerDown = (event: MouseEvent) => {
      if (
        actionsMenuContainerRef.current &&
        !actionsMenuContainerRef.current.contains(event.target as Node)
      ) {
        setIsActionsMenuOpen(false);
      }
    };

    // Capture phase ensures Escape closes the Actions menu before any outer dialog/drawer listener.
    window.addEventListener('keydown', handleKeyDown, true);
    document.addEventListener('mousedown', handlePointerDown);

    return () => {
      window.removeEventListener('keydown', handleKeyDown, true);
      document.removeEventListener('mousedown', handlePointerDown);
    };
  }, [isActionsMenuOpen]);

  const contextLabel = panelContext.issueKey
    ? `Jira Issue: ${panelContext.issueKey}`
    : panelContext.contentId
    ? `Confluence Page: ${panelContext.contentId}`
    : panelContext.projectKey
    ? `Jira Project: ${panelContext.projectKey}`
    : panelContext.isConfluence
    ? 'Confluence Global View'
    : 'Jira Project View';

  const runMenuAction = (handler: () => void) => {
    setIsActionsMenuOpen(false);
    handler();
  };

  return (
    <header className="mt-header no-print">
      <div className="mt-header-top">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              background: 'var(--mt-brand-bg)',
              borderRadius: 8,
              padding: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldCheck size={compact ? 18 : 22} color="var(--ds-text-inverse, #ffffff)" />
          </div>
          <div>
            <div
              style={{
                fontSize: compact ? 15 : 18,
                fontWeight: 800,
                color: 'var(--mt-text-primary)',
                letterSpacing: '-0.2px',
              }}
            >
              MedTrace{' '}
              {!compact && (
                <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--mt-text-muted)' }}>
                  | IEC 62304 &amp; FDA 21 CFR Part 11 Living Traceability Engine
                </span>
              )}
            </div>
            <div
              style={{
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                marginTop: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                flexWrap: 'wrap',
              }}
            >
              <span>
                Device System: <b>{summary.projectName}</b> • {contextLabel}
              </span>
              {isUninitialized ? (
                <span
                  style={{
                    padding: '1px 7px',
                    borderRadius: 3,
                    background: 'var(--mt-warning-bg)',
                    border: '1px solid var(--mt-warning-border)',
                    color: 'var(--mt-warning-text)',
                    fontWeight: 800,
                    fontSize: 9,
                    letterSpacing: '0.4px',
                  }}
                  title="No compliance trace links are initialized yet. Run Sync Live Atlassian or Seed Demo Suite."
                >
                  {isLive ? 'UNINITIALIZED (NO DATA)' : 'DEMO — UNINITIALIZED (NO DATA)'}
                </span>
              ) : isLive ? (
                <span
                  style={{
                    padding: '1px 7px',
                    borderRadius: 3,
                    background: 'var(--mt-success-bg)',
                    border: '1px solid var(--mt-success-border)',
                    color: 'var(--mt-success-text)',
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
                    background: 'var(--mt-warning-bg)',
                    border: '1px solid var(--mt-warning-border)',
                    color: 'var(--mt-warning-text)',
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
          <div style={{ display: 'flex', background: 'var(--mt-bg-neutral)', padding: 2, borderRadius: 6 }}>
            <button
              type="button"
              aria-pressed={activeView === 'graph'}
              onClick={() => onToggleView('graph')}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                border: 'none',
                borderRadius: 5,
                background: activeView === 'graph' ? 'var(--mt-bg-surface)' : 'transparent',
                boxShadow: activeView === 'graph' ? '0 1px 3px rgba(9, 30, 66, 0.12)' : 'none',
                color: activeView === 'graph' ? 'var(--mt-brand-text)' : 'var(--mt-text-secondary)',
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
                background: activeView === 'table' ? 'var(--mt-bg-surface)' : 'transparent',
                boxShadow: activeView === 'table' ? '0 1px 3px rgba(9, 30, 66, 0.12)' : 'none',
                color: activeView === 'table' ? 'var(--mt-brand-text)' : 'var(--mt-text-secondary)',
              }}
            >
              <Table size={14} /> Matrix
            </button>
          </div>

          {!compact && (
            <>
              <button
                type="button"
                onClick={onSyncLive}
                disabled={mutationBusy}
                className="mt-btn"
                style={{
                  border: '1.5px solid var(--mt-success-bold)',
                  background: 'var(--mt-success-bg)',
                  color: 'var(--mt-success-text)',
                }}
              >
                <RefreshCw size={14} />
                {isSyncingLive ? 'Syncing Tenant...' : 'Sync Live Atlassian'}
              </button>

              <button
                type="button"
                onClick={onSeed}
                disabled={mutationBusy}
                className="mt-btn"
                style={{
                  border: '1.5px solid var(--mt-brand-bg)',
                  background: 'var(--mt-brand-subtle-bg)',
                  color: 'var(--mt-brand-text)',
                }}
              >
                <Sparkles size={14} />
                {isSeeding ? 'Seeding Demo...' : 'Seed Demo Suite'}
              </button>

              <button
                type="button"
                onClick={onAnalyzeBlastRadius}
                disabled={mutationBusy || isAnalyzingBlastRadius}
                className="mt-btn"
                style={{
                  border: '1.5px solid var(--mt-warning-border)',
                  background: 'var(--mt-warning-bg)',
                  color: 'var(--mt-warning-text)',
                }}
              >
                <Zap size={14} color="var(--mt-warning-text)" />
                {isAnalyzingBlastRadius ? 'Analyzing...' : 'Blast Radius'}
              </button>
            </>
          )}

          <button
            type="button"
            onClick={onTestTransition}
            disabled={mutationBusy}
            className="mt-btn"
            style={{
              border: '1.5px solid var(--mt-danger-bold)',
              background: 'var(--mt-danger-bg)',
              color: 'var(--mt-danger-text)',
            }}
          >
            <ShieldAlert size={14} />
            Test Human Gate
          </button>

          {compact ? (
            <div ref={actionsMenuContainerRef} style={{ position: 'relative' }}>
              <button
                ref={actionsTriggerRef}
                type="button"
                aria-haspopup="menu"
                aria-expanded={isActionsMenuOpen}
                aria-controls="mt-compact-actions-menu"
                onClick={() => setIsActionsMenuOpen((prev) => !prev)}
                className="mt-btn"
                style={{
                  border: '1px solid var(--mt-border-input)',
                  background: 'var(--mt-bg-surface)',
                  color: 'var(--mt-text-primary)',
                }}
              >
                Actions ▾
              </button>
              {isActionsMenuOpen && (
                <div
                  ref={actionsMenuRef}
                  id="mt-compact-actions-menu"
                  role="menu"
                  aria-label="Compliance actions"
                  style={{
                    position: 'absolute',
                    top: 'calc(100% + 4px)',
                    right: 0,
                    minWidth: 210,
                    background: 'var(--mt-bg-overlay)',
                    border: '1px solid var(--mt-border)',
                    borderRadius: 6,
                    boxShadow: '0 6px 20px rgba(9, 30, 66, 0.2)',
                    padding: 4,
                    zIndex: 1200,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 2,
                  }}
                >
                  <button
                    type="button"
                    role="menuitem"
                    disabled={mutationBusy}
                    onClick={() => runMenuAction(onSyncLive)}
                    className="mt-btn"
                    style={menuItemStyle}
                  >
                    <RefreshCw size={14} />
                    {isSyncingLive ? 'Syncing Tenant...' : 'Sync Live Atlassian'}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    disabled={mutationBusy}
                    onClick={() => runMenuAction(onSeed)}
                    className="mt-btn"
                    style={menuItemStyle}
                  >
                    <Sparkles size={14} />
                    {isSeeding ? 'Seeding Demo...' : 'Seed Demo Suite'}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    disabled={mutationBusy || isAnalyzingBlastRadius}
                    onClick={() => runMenuAction(onAnalyzeBlastRadius)}
                    className="mt-btn"
                    style={menuItemStyle}
                  >
                    <Zap size={14} />
                    {isAnalyzingBlastRadius ? 'Analyzing...' : 'Blast Radius'}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => runMenuAction(onOpenAuditLog)}
                    className="mt-btn"
                    style={menuItemStyle}
                  >
                    <ScrollText size={14} />
                    Audit Log ({summary.auditEntryCount ?? 0})
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => runMenuAction(onOpenExport)}
                    className="mt-btn"
                    style={menuItemStyle}
                  >
                    <FileDown size={14} />
                    Export Dossier
                  </button>
                </div>
              )}
            </div>
          ) : (
            <>
              <button
                type="button"
                onClick={onOpenAuditLog}
                className="mt-btn"
                style={{
                  border: '1px solid var(--mt-border-input)',
                  background: 'var(--mt-bg-surface)',
                  color: 'var(--mt-text-primary)',
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
                  background: 'var(--mt-brand-bg)',
                  color: 'var(--ds-text-inverse, #ffffff)',
                  boxShadow: '0 2px 4px rgba(0, 82, 204, 0.25)',
                }}
              >
                <FileDown size={14} /> Export Dossier
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stat Metric Cards */}
      <div className="mt-metrics-grid">
        <div style={cardStyle}>
          <div style={cardLabel}>IEC 62304 VERIFICATION COVERAGE</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
            <span
              style={{
                fontSize: 22,
                fontWeight: 800,
                color:
                  !isUninitialized && summary.verifiedPercentage === 100
                    ? 'var(--mt-success-text)'
                    : 'var(--mt-danger-text)',
              }}
            >
              {summary.verifiedPercentage}%
            </span>
            <span style={{ fontSize: 11, color: 'var(--mt-text-muted)' }}>
              ({verifiedCount}/{summary.totalHazards} Hazards)
            </span>
          </div>
        </div>

        <div style={cardStyle}>
          <div style={cardLabel}>ISO 14971 RISK CLASSES</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
            <span
              style={{
                fontSize: 22,
                fontWeight: 800,
                color: summary.classCCount > 0 ? 'var(--mt-danger-text)' : 'var(--mt-text-primary)',
              }}
            >
              {summary.classCCount}
            </span>
            <span style={{ fontSize: 11, color: 'var(--mt-text-secondary)', fontWeight: 600 }}>
              Class C • C: {summary.classCCount} • B: {summary.classBCount} • A: {summary.classACount}
            </span>
          </div>
        </div>

        <div
          style={{
            ...cardStyle,
            borderLeft: `4px solid ${gateBlocked ? 'var(--mt-danger-bold)' : 'var(--mt-success-bold)'}`,
          }}
        >
          <div style={cardLabel}>JIRA HUMAN RELEASE GATE</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
            {isUninitialized ? (
              <>
                <ShieldAlert size={18} color="var(--mt-danger-text)" />
                <span style={{ fontSize: 13, fontWeight: 800, color: 'var(--mt-danger-text)' }}>
                  UNINITIALIZED (NO DATA)
                </span>
              </>
            ) : summary.releaseBlocked ? (
              <>
                <ShieldAlert size={18} color="var(--mt-danger-text)" />
                <span style={{ fontSize: 13, fontWeight: 800, color: 'var(--mt-danger-text)' }}>
                  RELEASE BLOCKED
                </span>
              </>
            ) : (
              <>
                <ShieldCheck size={18} color="var(--mt-success-text)" />
                <span style={{ fontSize: 13, fontWeight: 800, color: 'var(--mt-success-text)' }}>
                  AUDIT READY (ZERO GAPS)
                </span>
              </>
            )}
          </div>
          {gateBlocked && blockingCount > 0 && (
            <div
              style={{
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                marginTop: 4,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={summary.blockingReasons.join('\n')}
            >
              {blockingCount} blocking {blockingCount === 1 ? 'reason' : 'reasons'}: {summary.blockingReasons[0]}
            </div>
          )}
        </div>

        <div style={cardStyle}>
          <div style={cardLabel}>SIGNATURE EVIDENCE STATUS</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
            {isUninitialized ? (
              <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--mt-text-muted)' }}>
                No Records
              </span>
            ) : driftCount > 0 && unsignedOrInvalidCount > 0 ? (
              <span style={{ fontSize: 18, fontWeight: 800, color: 'var(--mt-warning-text)' }}>
                {driftCount} Drifted, {unsignedOrInvalidCount} Unsigned
              </span>
            ) : driftCount > 0 ? (
              <span style={{ fontSize: 22, fontWeight: 800, color: 'var(--mt-warning-text)' }}>
                {driftCount} Drifted
              </span>
            ) : invalidSigCount > 0 ? (
              <span style={{ fontSize: 18, fontWeight: 800, color: 'var(--mt-warning-text)' }}>
                {invalidSigCount} Unsigned / Invalid
              </span>
            ) : (
              <span style={{ fontSize: 22, fontWeight: 800, color: 'var(--mt-success-text)' }}>
                All Valid
              </span>
            )}
            <span style={{ fontSize: 11, color: 'var(--mt-text-muted)' }}>21 CFR Part 11 SHA-256</span>
          </div>
        </div>
      </div>
    </header>
  );
};

const cardStyle: React.CSSProperties = {
  background: 'var(--mt-bg-surface-subtle)',
  borderRadius: 6,
  padding: '10px 14px',
  border: '1px solid var(--mt-border-subtle)',
};

const cardLabel: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 800,
  letterSpacing: '0.6px',
  color: 'var(--mt-text-secondary)',
};

const menuItemStyle: React.CSSProperties = {
  width: '100%',
  justifyContent: 'flex-start',
  border: 'none',
  background: 'transparent',
  color: 'var(--mt-text-primary)',
  textAlign: 'left',
  padding: '8px 10px',
  borderRadius: 4,
};
