import type { ScannerAdapter } from "@synsec/scanner-sdk";
import {
  createOciScannerProcessRunner,
  type OciScannerSandboxOptions,
} from "@synsec/scanner-sdk/oci-sandbox";
import { CheckovAdapter } from "./checkov.js";
import { GrypeAdapter } from "./grype.js";
import { SyftAdapter } from "./syft.js";

export interface OciIsolatedScannerOptions extends OciScannerSandboxOptions {}
export interface OciIsolatedDependencyScannerOptions extends OciIsolatedScannerOptions {}

/**
 * Build the scanner subset whose adapters support the enforced OCI process boundary for both
 * availability and scan execution.
 *
 * The digest-pinned image must contain `checkov`, `grype`, and `syft`. Because the sandbox deliberately
 * uses network=none, production images must also contain any vulnerability database/cache material
 * required by the pinned Grype version. Checkov's bundled IaC checks do not require network access;
 * SynSec never widens the container to bridge networking to make an unprepared scanner image succeed.
 *
 * This helper intentionally returns only adapters that are fully runner-injectable. It must not be
 * merged with host-backed built-ins and represented as complete scanner isolation.
 */
export function createOciIsolatedScanners(
  options: OciIsolatedScannerOptions,
): ScannerAdapter[] {
  const runner = createOciScannerProcessRunner(options);
  return [new CheckovAdapter(runner), new GrypeAdapter(runner), new SyftAdapter(runner)];
}

/**
 * Backward-compatible dependency/SBOM-only composition for callers that intentionally do not want
 * IaC scanning. This remains an enforced OCI path and does not imply broader scanner isolation.
 */
export function createOciIsolatedDependencyScanners(
  options: OciIsolatedDependencyScannerOptions,
): ScannerAdapter[] {
  const runner = createOciScannerProcessRunner(options);
  return [new GrypeAdapter(runner), new SyftAdapter(runner)];
}
