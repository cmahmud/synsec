export type SynSecScannerIsolationRuntime = "container" | "sandbox";
export type SynSecScannerIsolationNetworkPolicy = "none" | "egress-filtered";

export interface SynSecScannerIsolationProfile {
  schemaVersion: 1;
  runtime: SynSecScannerIsolationRuntime;
  cpuLimit: true;
  memoryLimit: true;
  networkPolicy: SynSecScannerIsolationNetworkPolicy;
  repositoryReadOnly: true;
  rootFilesystemReadOnly: true;
  scratchSeparated: true;
  credentialsExcluded: true;
  durableStateExcluded: true;
  privileged: false;
  allowPrivilegeEscalation: false;
  runAsNonRoot: true;
  capabilitiesDropped: true;
  hostNetwork: false;
  hostPid: false;
  hostIpc: false;
  hostSocketMounts: false;
}

export type SynSecScannerIsolationControl =
  | "supported-runtime"
  | "cpu-limit"
  | "memory-limit"
  | "restricted-network"
  | "read-only-repository"
  | "read-only-root-filesystem"
  | "separate-scratch"
  | "credentials-excluded"
  | "durable-state-excluded"
  | "not-privileged"
  | "no-privilege-escalation"
  | "run-as-non-root"
  | "capabilities-dropped"
  | "no-host-network"
  | "no-host-pid"
  | "no-host-ipc"
  | "no-host-socket-mounts";

export interface SynSecScannerIsolationAssessment {
  complete: boolean;
  missing: SynSecScannerIsolationControl[];
  interpretation: "declared-infrastructure-controls-not-runtime-certification";
}

export const REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS = [
  "supported-runtime",
  "cpu-limit",
  "memory-limit",
  "restricted-network",
  "read-only-repository",
  "read-only-root-filesystem",
  "separate-scratch",
  "credentials-excluded",
  "durable-state-excluded",
  "not-privileged",
  "no-privilege-escalation",
  "run-as-non-root",
  "capabilities-dropped",
  "no-host-network",
  "no-host-pid",
  "no-host-ipc",
  "no-host-socket-mounts",
] as const satisfies readonly SynSecScannerIsolationControl[];

function hasControl(profile: Partial<SynSecScannerIsolationProfile>, control: SynSecScannerIsolationControl): boolean {
  switch (control) {
    case "supported-runtime":
      return profile.runtime === "container" || profile.runtime === "sandbox";
    case "cpu-limit":
      return profile.cpuLimit === true;
    case "memory-limit":
      return profile.memoryLimit === true;
    case "restricted-network":
      return profile.networkPolicy === "none" || profile.networkPolicy === "egress-filtered";
    case "read-only-repository":
      return profile.repositoryReadOnly === true;
    case "read-only-root-filesystem":
      return profile.rootFilesystemReadOnly === true;
    case "separate-scratch":
      return profile.scratchSeparated === true;
    case "credentials-excluded":
      return profile.credentialsExcluded === true;
    case "durable-state-excluded":
      return profile.durableStateExcluded === true;
    case "not-privileged":
      return profile.privileged === false;
    case "no-privilege-escalation":
      return profile.allowPrivilegeEscalation === false;
    case "run-as-non-root":
      return profile.runAsNonRoot === true;
    case "capabilities-dropped":
      return profile.capabilitiesDropped === true;
    case "no-host-network":
      return profile.hostNetwork === false;
    case "no-host-pid":
      return profile.hostPid === false;
    case "no-host-ipc":
      return profile.hostIpc === false;
    case "no-host-socket-mounts":
      return profile.hostSocketMounts === false;
  }
}

/**
 * Assess a secret-free declaration of scanner sandbox controls.
 *
 * This is intentionally stricter than the legacy high-level deployment declaration: it makes
 * common container-escape and credential-boundary assumptions explicit so production deployment
 * tooling can fail closed before scanner subprocesses are activated. It does not inspect the host
 * or certify that the declared controls are actually enforced by Docker, Kubernetes, or another
 * sandbox runtime.
 */
export function assessSynSecScannerIsolationProfile(
  profile: Partial<SynSecScannerIsolationProfile> | undefined,
): SynSecScannerIsolationAssessment {
  const missing = REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS.filter(
    (control) => !profile || !hasControl(profile, control),
  );
  return {
    complete: profile?.schemaVersion === 1 && missing.length === 0,
    missing: profile?.schemaVersion === 1 ? [...missing] : [...REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS],
    interpretation: "declared-infrastructure-controls-not-runtime-certification",
  };
}
