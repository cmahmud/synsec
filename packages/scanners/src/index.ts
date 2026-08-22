import type { ScannerAdapter } from "@synsec/scanner-sdk";
import { CheckovAdapter } from "./checkov.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { GrypeAdapter } from "./grype.js";
import { OpengrepAdapter } from "./opengrep.js";
import { OsvScannerAdapter } from "./osv.js";
import { TrivyAdapter } from "./trivy.js";

export { CheckovAdapter, parseCheckovJson } from "./checkov.js";
export { GitleaksAdapter, parseGitleaksJson } from "./gitleaks.js";
export { GrypeAdapter, parseGrypeJson } from "./grype.js";
export { OpengrepAdapter, parseOpengrepJson } from "./opengrep.js";
export { OsvScannerAdapter, parseOsvJson } from "./osv.js";
export { TrivyAdapter, parseTrivyJson } from "./trivy.js";

export function builtInScanners(): ScannerAdapter[] {
  return [
    new OpengrepAdapter(),
    new GitleaksAdapter(),
    new OsvScannerAdapter(),
    new TrivyAdapter(),
    new GrypeAdapter(),
    new CheckovAdapter(),
  ];
}
