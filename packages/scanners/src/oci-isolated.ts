import type { ScannerAdapter } from "@synsec/scanner-sdk";
import {
  createOciScannerProcessRunner,
  type OciScannerSandboxOptions,
} from "@synsec/scanner-sdk/oci-sandbox";
import { GrypeAdapter } from "./grype.js";
import { SyftAdapter } from "./syft.js";

export interface OciIsolatedDependencyScannerOptions extends OciScannerSandboxOptions {}

/**
 * Build the dependency/SBOM subset whose adapters currently support the enforced OCI process
 * boundary for both availability and scan execution.
 *
 * The digest-pinned image must contain both `grype` and `syft`. Because the sandbox deliberately
 * uses network=none, production images must also contain any vulnerability database/cache material
 * required by the pinned Grype version. SynSec never widens the container to bridge networking to
 * make an unprepared image succeed.
 *
 * This helper intentionally returns only adapters that are fully runner-injectable. It must not be
 * merged with host-backed built-ins and represented as complete scanner isolation.
 */
export function createOciIsolatedDependencyScanners(
  options: OciIsolatedDependencyScannerOptions,
): ScannerAdapter[] {
  const runner = createOciScannerProcessRunner(options);
  return [new GrypeAdapter(runner), new SyftAdapter(runner)];
}
