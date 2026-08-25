import { AsyncLocalStorage } from "node:async_hooks";
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
export {
  createOciIsolatedDependencyScanners,
  type OciIsolatedDependencyScannerOptions,
} from "./oci-isolated.js";

const NATIVE_CHANGED_FILE_SCANNERS = new Set([
  "opengrep",
  "betterleaks",
  "gitleaks",
  "checkov",
  "trivy",
  "osv-scanner",
]);

export type BuiltInScannerFactory = () => ScannerAdapter[];
const scopedScannerFactory = new AsyncLocalStorage<BuiltInScannerFactory>();

/**
 * Whether a built-in adapter can ask its underlying scanner to execute against a bounded
 * changed-file target rather than scanning the whole repository and filtering findings later.
 * Individual adapters may still fail closed to repository execution for ambiguous local inputs.
 */
export function scannerSupportsNativeChangedFiles(scannerId: string): boolean {
  return NATIVE_CHANGED_FILE_SCANNERS.has(scannerId);
}

function defaultBuiltInScanners(): ScannerAdapter[] {
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

function validateFactoryOutput(scanners: ScannerAdapter[]): ScannerAdapter[] {
  if (!Array.isArray(scanners) || scanners.length === 0) {
    throw new Error("Scoped scanner factory must provide at least one scanner adapter.");
  }
  const ids = new Set<string>();
  for (const scanner of scanners) {
    if (!scanner || typeof scanner.id !== "string" || !scanner.id.trim()) {
      throw new Error("Scoped scanner factory returned an invalid scanner adapter.");
    }
    if (ids.has(scanner.id)) throw new Error("Scoped scanner factory returned duplicate scanner ids.");
    ids.add(scanner.id);
  }
  return scanners;
}

/**
 * Return the scanner set active for the current asynchronous execution context.
 *
 * Normal CLI/local scans continue to use the host-backed built-ins. Production hosting code can
 * establish a narrower process-boundary-specific factory for one asynchronous operation without
 * mutating global adapter state or bleeding configuration into concurrent scans.
 */
export function builtInScanners(): ScannerAdapter[] {
  const factory = scopedScannerFactory.getStore();
  return factory ? validateFactoryOutput(factory()) : defaultBuiltInScanners();
}

/**
 * Run one asynchronous operation with a context-local scanner factory.
 *
 * This is an execution-composition primitive, not an isolation assertion by itself. Callers are
 * responsible for supplying adapters whose process runner actually enforces the claimed boundary.
 * AsyncLocalStorage keeps concurrent hosted jobs from replacing one another's scanner set.
 */
export function withBuiltInScannerFactory<T>(
  factory: BuiltInScannerFactory,
  operation: () => Promise<T>,
): Promise<T> {
  if (typeof factory !== "function" || typeof operation !== "function") {
    throw new Error("Scoped scanner factory and operation are required.");
  }
  return scopedScannerFactory.run(factory, operation);
}
