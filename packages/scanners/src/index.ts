import type { ScannerAdapter } from "@synsec/scanner-sdk";
import { BetterleaksAdapter } from "./betterleaks.js";
import { CheckovAdapter } from "./checkov.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { GrypeAdapter } from "./grype.js";
import { OpengrepAdapter } from "./opengrep.js";
import { OsvScannerAdapter } from "./osv.js";
import { ScorecardAdapter } from "./scorecard.js";
import { SyftAdapter } from "./syft.js";
import { TrivyAdapter } from "./trivy.js";

export { BetterleaksAdapter, parseBetterleaksJson } from "./betterleaks.js";
export { CheckovAdapter, buildCheckovArguments, parseCheckovJson } from "./checkov.js";
export { GitleaksAdapter, normalizeGitleaksChangedFiles, parseGitleaksJson } from "./gitleaks.js";
export { GrypeAdapter, parseGrypeJson } from "./grype.js";
export { OpengrepAdapter, parseOpengrepJson } from "./opengrep.js";
export { OsvScannerAdapter, buildOsvArguments, parseOsvJson } from "./osv.js";
export { parseSarifJson } from "./sarif.js";
export { ScorecardAdapter, parseScorecardJson } from "./scorecard.js";
export { SyftAdapter, parseSyftJson } from "./syft.js";
export { TrivyAdapter, normalizeTrivyChangedFiles, parseTrivyJson } from "./trivy.js";

const NATIVE_CHANGED_FILE_SCANNERS = new Set([
  "opengrep",
  "betterleaks",
  "gitleaks",
  "checkov",
  "trivy",
  "osv-scanner",
]);

/**
 * Whether a built-in adapter can ask its underlying scanner to execute against a bounded
 * changed-file target rather than scanning the whole repository and filtering findings later.
 * Individual adapters may still fail closed to repository execution for ambiguous local inputs.
 */
export function scannerSupportsNativeChangedFiles(scannerId: string): boolean {
  return NATIVE_CHANGED_FILE_SCANNERS.has(scannerId);
}

export function builtInScanners(): ScannerAdapter[] {
  return [
    new OpengrepAdapter(),
    new BetterleaksAdapter(),
    new GitleaksAdapter(),
    new OsvScannerAdapter(),
    new TrivyAdapter(),
    new GrypeAdapter(),
    new CheckovAdapter(),
    new SyftAdapter(),
    new ScorecardAdapter(),
  ];
}
