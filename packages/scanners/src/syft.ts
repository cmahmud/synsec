import type { SbomArtifact, SbomPackage, ScanResult } from "@synsec/core";
import type {
  ScannerAdapter,
  ScannerAvailability,
  ScannerContext,
  ScannerProcessRunner,
} from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asRecord, asString, commandAvailability, relativeLike, safeJson } from "./utils.js";

function licenseValues(value: unknown): string[] | undefined {
  const values = asArray(value)
    .flatMap((entry) => {
      if (typeof entry === "string") return [entry];
      const record = asRecord(entry);
      if (!record) return [];
      const expression = asString(record.spdxExpression);
      const raw = asString(record.value);
      return expression ? [expression] : raw ? [raw] : [];
    })
    .map((item) => item.trim())
    .filter(Boolean);
  return values.length > 0 ? [...new Set(values)] : undefined;
}

function locationValues(value: unknown, root: string): string[] | undefined {
  const values = asArray(value)
    .map(asRecord)
    .map((location) => relativeLike(asString(location?.path), root))
    .filter((item): item is string => Boolean(item));
  return values.length > 0 ? [...new Set(values)] : undefined;
}

function packageFrom(value: unknown, root: string): SbomPackage | undefined {
  const item = asRecord(value);
  if (!item) return undefined;
  const name = asString(item.name);
  if (!name) return undefined;

  const pkg: SbomPackage = { name };
  const version = asString(item.version);
  const type = asString(item.type);
  const purl = asString(item.purl);
  const licenses = licenseValues(item.licenses);
  const locations = locationValues(item.locations, root);
  if (version) pkg.version = version;
  if (type) pkg.type = type;
  if (purl) pkg.purl = purl;
  if (licenses) pkg.licenses = licenses;
  if (locations) pkg.locations = locations;
  return pkg;
}

export function parseSyftJson(raw: string, root: string, generatedAt = new Date().toISOString()): SbomArtifact {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) throw new Error("Syft returned an unsupported JSON document.");

  const packages = asArray(parsed.artifacts)
    .map((value) => packageFrom(value, root))
    .filter((value): value is SbomPackage => Boolean(value));

  const descriptor = asRecord(parsed.descriptor);
  const source = asRecord(parsed.source);
  const distro = asRecord(parsed.distro);

  return {
    type: "sbom",
    format: "syft-json",
    producer: "syft",
    generatedAt,
    packageCount: packages.length,
    packages,
    metadata: {
      syftVersion: asString(descriptor?.version),
      sourceId: asString(source?.id),
      sourceName: asString(source?.name),
      sourceVersion: asString(source?.version),
      distroName: asString(distro?.name),
      distroVersion: asString(distro?.version),
    },
  };
}

export class SyftAdapter implements ScannerAdapter {
  readonly id = "syft";
  readonly displayName = "Syft";
  readonly capabilities = ["sbom"] as const;

  constructor(private readonly processRunner: ScannerProcessRunner = runProcess) {}

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("syft", ["version"], this.displayName, this.processRunner);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await this.processRunner(
      "syft",
      [`dir:${context.target.path}`, "-o", "syft-json"],
      { timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
    );
    if (output.exitCode !== 0) {
      throw new Error(`Syft scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    }
    const completedAt = new Date().toISOString();
    return {
      scanner: this.id,
      startedAt,
      completedAt,
      target: context.target,
      findings: [],
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
      artifacts: [parseSyftJson(output.stdout, context.target.path, completedAt)],
    };
  }
}
