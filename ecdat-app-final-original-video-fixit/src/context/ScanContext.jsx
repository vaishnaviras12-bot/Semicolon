import React, { createContext, useContext, useState, useMemo, useCallback, useEffect } from 'react';
import {
  BAND_RANK, actionableFindings, hndlFindings, signatureOnlyFindings,
  estimateMigrationYears, QDAY_DISTRIBUTION_YEARS_FROM_NOW, isLibraryOnlyFinding,
} from '../data/findings.js';
import { computeBreach } from '../utils/mosca.js';
import {
  uploadScanTarget, listScans, getScanStatus, getScanFindings,
  getScanCBOM, getScanCycloneDX, getScanRisk, getScanMosca, getScanMigration,
  getScanCompliance, getScanRemediation, updateRemediationStatus, deleteScan
} from '../api/index.js';
import { useAuth } from './AuthContext.jsx';
import { formatDate, formatDateTime } from '../utils/datetime.js';

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const { user } = useAuth();

  // --- layout / theme ---
  const [theme, setTheme] = useState('dark');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const toggleTheme = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), []);
  const toggleSidebar = useCallback(() => setSidebarOpen((o) => !o), []);

  // --- Real API scan state machine ---
  const [scanState, setScanState] = useState('idle'); // 'idle' | 'scanning' | 'complete' | 'error'
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStageText, setScanStageText] = useState('Idle');
  const [activeScanId, setActiveScanId] = useState(null);
  const [activeFileName, setActiveFileName] = useState(null);
  const [activeScanDate, setActiveScanDate] = useState(null);
  const [findings, setFindings] = useState([]);
  const [cbom, setCbom] = useState(null);
  const [cyclonedx, setCyclonedx] = useState(null);
  const [riskData, setRiskData] = useState(null);
  const [moscaData, setMoscaData] = useState(null);
  const [migrationData, setMigrationData] = useState(null);
  const [complianceData, setComplianceData] = useState(null);
  const [scansList, setScansList] = useState([]);
  const [scanError, setScanError] = useState(null);
  const [scanLoading, setScanLoading] = useState(true);

  // Clear state on logout or user change
  const clearActiveScan = useCallback(() => {
    setScanState('idle');
    setActiveScanId(null);
    setActiveFileName(null);
    setActiveScanDate(null);
    setFindings([]);
    setCbom(null);
    setCyclonedx(null);
    setRiskData(null);
    setMoscaData(null);
    setMigrationData(null);
    setComplianceData(null);
    setScanError(null);
  }, []);

  const loadScanResults = useCallback(async (scanId, fileName = 'Scan Target') => {
    try {
      const [
        fetchedFindings,
        fetchedCbom,
        fetchedCycloneDx,
        fetchedRisk,
        fetchedMosca,
        fetchedMigration,
        fetchedCompliance,
        remData
      ] = await Promise.all([
        getScanFindings(scanId).catch(() => []),
        getScanCBOM(scanId).catch(() => null),
        getScanCycloneDX(scanId).catch(() => null),
        getScanRisk(scanId).catch(() => null),
        getScanMosca(scanId).catch(() => null),
        getScanMigration(scanId).catch(() => null),
        getScanCompliance(scanId).catch(() => null),
        getScanRemediation(scanId).catch(() => ({ remediations: {} })),
      ]);

      const safeFindings = Array.isArray(fetchedFindings) ? fetchedFindings : [];
      const safeCbom = (fetchedCbom && typeof fetchedCbom === 'object' && !fetchedCbom.detail) ? fetchedCbom : null;
      const safeCycloneDx = (fetchedCycloneDx && typeof fetchedCycloneDx === 'object' && !fetchedCycloneDx.detail) ? fetchedCycloneDx : null;
      const safeRisk = (fetchedRisk && typeof fetchedRisk === 'object' && !fetchedRisk.detail) ? fetchedRisk : null;
      const safeMosca = (fetchedMosca && typeof fetchedMosca === 'object' && !fetchedMosca.detail) ? fetchedMosca : null;
      const safeMigration = (fetchedMigration && typeof fetchedMigration === 'object' && !fetchedMigration.detail) ? fetchedMigration : null;
      const safeCompliance = (fetchedCompliance && typeof fetchedCompliance === 'object' && !fetchedCompliance.detail) ? fetchedCompliance : null;

      setActiveScanId(scanId);
      setActiveFileName(fileName);
      setFindings(safeFindings);
      setCbom(safeCbom);
      setCyclonedx(safeCycloneDx);
      setRiskData(safeRisk);
      setMoscaData(safeMosca);
      setMigrationData(safeMigration);
      setComplianceData(safeCompliance);

      if (remData?.remediations) {
        const statuses = {};
        const choices = {};
        Object.entries(remData.remediations).forEach(([fid, val]) => {
          if (val?.status) statuses[fid] = val.status;
          if (val?.choice) choices[fid] = val.choice;
        });
        setRemediationStatus(statuses);
        setPatchChoice(choices);
      }

      setScanState('complete');
    } catch (err) {
      console.error("Failed loading scan results from backend:", err);
      setScanError("Failed to load scan results from backend.");
    }
  }, []);

  // Load scan history and active scan findings
  const refreshScansHistory = useCallback(async () => {
    if (!user) {
      setScansList([]);
      clearActiveScan();
      setScanLoading(false);
      return [];
    }
    try {
      const history = await listScans();
      setScansList(history || []);
      if (history && history.length > 0 && !activeScanId) {
        const latest = history[0];
        await loadScanResults(latest.scan_id, latest.target_name);
      }
      return history || [];
    } catch (err) {
      console.warn("Backend API unreachable or unauthorized:", err.message);
      setScansList([]);
      return [];
    } finally {
      setScanLoading(false);
    }
  }, [user, clearActiveScan, activeScanId, loadScanResults]);

  // Update history when user changes
  useEffect(() => {
    refreshScansHistory();
  }, [user, refreshScansHistory]);

  // --- Trigger Real Backend Scan ---
  const beginScan = useCallback(async (input) => {
    setScanError(null);
    const file = typeof input === 'object' && input?.name ? input : null;
    const fileName = file?.name || (typeof input === 'string' ? input : 'scan_target.zip');
    
    setActiveFileName(fileName);
    setScanState('scanning');
    setScanProgress(5);
    setScanStageText('Uploading target to backend...');

    try {
      let scanMeta;
      if (file) {
        scanMeta = await uploadScanTarget(file);
      } else {
        scanMeta = await uploadScanTarget(new File(["sample"], fileName));
      }

      const scanId = scanMeta.scan_id;
      setActiveScanId(scanId);

      // Poll status until complete or failed
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await getScanStatus(scanId);
          setScanProgress(statusRes.progress_percentage || 50);
          setScanStageText(statusRes.stage || 'Analyzing target...');

          if (statusRes.status === 'completed') {
            clearInterval(pollInterval);
            setActiveScanDate(formatDate(new Date()));
            await loadScanResults(scanId, fileName);
            await refreshScansHistory();
          } else if (statusRes.status === 'failed') {
            clearInterval(pollInterval);
            setScanState('error');
            setScanError(statusRes.stage || 'Scan processing failed on backend.');
          }
        } catch (pollErr) {
          clearInterval(pollInterval);
          setScanState('error');
          setScanError('Connection error while polling scan status.');
        }
      }, 1000);

    } catch (err) {
      setScanState('error');
      setScanError(err.message || 'Failed to start scan on backend.');
    }
  }, [loadScanResults, refreshScansHistory]);

  // --- Delete scan by ID ---
  const removeScanById = useCallback(async (scanId) => {
    try {
      await deleteScan(scanId);
      if (activeScanId === scanId) {
        clearActiveScan();
      }
      await refreshScansHistory();
    } catch (err) {
      console.error("Failed deleting scan:", err);
      throw err;
    }
  }, [activeScanId, clearActiveScan, refreshScansHistory]);

  // --- PQC Remediation state ---
  const [patchChoice, setPatchChoice] = useState({});
  const [remediationStatus, setRemediationStatus] = useState({});

  const setChoice = useCallback((findingId, choice) => {
    setPatchChoice((prev) => ({ ...prev, [findingId]: choice }));
    if (activeScanId) {
      updateRemediationStatus(activeScanId, findingId, remediationStatus[findingId] || 'pending', choice).catch(console.error);
    }
  }, [activeScanId, remediationStatus]);

  const setStatus = useCallback((findingId, status) => {
    setRemediationStatus((prev) => ({ ...prev, [findingId]: status }));
    if (activeScanId) {
      updateRemediationStatus(activeScanId, findingId, status, patchChoice[findingId] || 'bridge').catch(console.error);
    }
  }, [activeScanId, patchChoice]);

  // --- Mosca Timeline parameters ---
  const defaultPortfolioX = useMemo(() => {
    const years = hndlFindings(findings).map((f) => f.mosca_x || 0);
    return years.length ? Math.max(...years) : 5;
  }, [findings]);

  const defaultPortfolioY = useMemo(() => {
    const years = hndlFindings(findings).map((f) => f.mosca_y || 0);
    return years.length ? +Math.max(...years).toFixed(2) : 0.5;
  }, [findings]);

  const [portfolioShelfLife, setPortfolioShelfLife] = useState(defaultPortfolioX);
  const [portfolioMigrationYears, setPortfolioMigrationYears] = useState(defaultPortfolioY);
  const [qdayDist, setQdayDist] = useState(QDAY_DISTRIBUTION_YEARS_FROM_NOW);

  useEffect(() => {
    setPortfolioShelfLife(defaultPortfolioX);
    setPortfolioMigrationYears(defaultPortfolioY);
  }, [defaultPortfolioX, defaultPortfolioY]);

  const resetMoscaOverrides = useCallback(() => {
    setPortfolioShelfLife(defaultPortfolioX);
    setPortfolioMigrationYears(defaultPortfolioY);
    setQdayDist(QDAY_DISTRIBUTION_YEARS_FROM_NOW);
  }, [defaultPortfolioX, defaultPortfolioY]);

  // --- Derived Metrics ---
  const operationalFindings = useMemo(() => {
    const list = Array.isArray(findings) ? findings : [];
    return list.filter((f) => !isLibraryOnlyFinding(f));
  }, [findings]);

  const libraryOnlyFindings = useMemo(() => {
    const list = Array.isArray(findings) ? findings : [];
    return list.filter((f) => isLibraryOnlyFinding(f));
  }, [findings]);

  const shorCount = useMemo(() => {
    return operationalFindings.filter((f) => f && (f.shor_vulnerable || f.shorVulnerable)).length;
  }, [operationalFindings]);

  const readinessScore = useMemo(() => {
    return operationalFindings.length > 0 ? Math.round(((operationalFindings.length - shorCount) / operationalFindings.length) * 100) : 100;
  }, [operationalFindings, shorCount]);

  const sortedFindings = useMemo(() => {
    return [...operationalFindings].sort((a, b) => (BAND_RANK[b?.risk_band || b?.band] || 0) - (BAND_RANK[a?.risk_band || a?.band] || 0));
  }, [operationalFindings]);

  const actionable = useMemo(() => actionableFindings(operationalFindings), [operationalFindings]);
  const hndlList = useMemo(() => hndlFindings(operationalFindings), [operationalFindings]);
  const signatureOnlyList = useMemo(() => signatureOnlyFindings(operationalFindings), [operationalFindings]);

  const portfolioBreach = useMemo(() => {
    const b = computeBreach(portfolioShelfLife, portfolioMigrationYears, qdayDist);
    return {
      ...b,
      breach: b.status !== 'safe',
      margin: -b.atP25,
    };
  }, [portfolioShelfLife, portfolioMigrationYears, qdayDist]);

  const worstBreach = portfolioBreach;

  const totalEffortHours = useMemo(() => {
    return operationalFindings.reduce((sum, f) => sum + (f?.migration_effort_hours || f?.remediation?.effortHours || 0), 0);
  }, [operationalFindings]);

  const remediatedCount = useMemo(() => {
    return operationalFindings.filter((f) => remediationStatus[f?.id] === 'merged').length;
  }, [operationalFindings, remediationStatus]);

  const value = {
    theme, toggleTheme, sidebarOpen, toggleSidebar,
    scanState, scanProgress, scanStageText, activeScanId, activeFileName, activeScanDate, scanError, scanLoading,
    beginScan, loadScanResults, removeScanById, clearActiveScan, scansList, refreshScansHistory,
    findings, operationalFindings, libraryOnlyFindings, cbom, cyclonedx, riskData, moscaData, migrationData, complianceData,
    sortedFindings, actionable, hndlList, signatureOnlyList,
    shorCount, readinessScore,
    patchChoice, setChoice, remediationStatus, setStatus, remediatedCount, totalEffortHours,
    portfolioShelfLife, setPortfolioShelfLife, portfolioMigrationYears, setPortfolioMigrationYears,
    qdayDist, setQdayDist, resetMoscaOverrides,
    portfolioBreach, worstBreach,
  };

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScan must be used inside ScanProvider');
  return ctx;
}
