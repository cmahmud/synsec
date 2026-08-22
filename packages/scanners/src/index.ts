import type { ScannerAdapter } from "@synsec/scanner-sdk";
import { BetterleaksAdapter } from "./betterleaks.js";
import { CheckovAdapter } from "./checkov.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { GrypeAdapter } from "./grype.js";
import { OpengrepAdapter } from "./opengrep.js";
import { OsvScannerAdapter } from "./osv.js";
import { ScorecardAdapter } from "./scorecard.js";
import { TrivyAdapter } from "./trivy.js";

export { BetterleaksAdapter, parseBetterleaksJson } from "./betterleaks.js";
export { CheckovAdapter, parseCheckovJson } from "./checkov.js";
export { GitleaksAdapter, parseGitleaksJson } from "./gitleaks.js";
export { GrypeAdapter, parseGrypeJson } from "./grype.js";
export { OpengrepAdapter, parseOpengrepJson } from "./opengrep.js";
export { OsvScannerAdapter, parseOsvJson } from "./osv.js";
export { ScorecardAdapter, parseScorecardJson } from "./scorecard.js";
export { TrivyAdapter, parseTrivyJson } from "./trivy.js";

export function builtInScanners(): ScannerAdapter[] {
  return [
    new OpengrepAdapter(),
    new BetterleaksAdapter(),
    new GitleaksAdapter(),
    new OsvScannerAdapter(),
    new TrivyAdapter(),
    new GrypeAdapter(),
    new CheckovAdapter(),
    new ScorecardAdapter(),
  ];
}
