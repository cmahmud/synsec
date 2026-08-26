import assert from "node:assert/strict";
import test from "node:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildOciScannerSandboxPlan,
  runOciSandboxedScanner,
} from "@synsec/scanner-sdk/oci-sandbox";

const digestImage = process.env.SYNSEC_TEST_OCI_IMAGE?.trim();
const integration = digestImage ? test : test.skip;
const fixtureImage = `registry.example.invalid/synsec/scanner@sha256:${"a".repeat(64)}`;

test("OCI scanner plan enforces immutable offline non-root resource and filesystem isolation", () => {
  const plan = buildOciScannerSandboxPlan("scanner", ["--json", "/workspace"], {
    image: fixtureImage,
    repositoryRoot: "/srv/synsec/workspaces/job-1",
    cpuLimit: 1.5,
    memoryBytes: 512 * 1024 * 1024,
    pidsLimit: 128,
    scratchBytes: 64 * 1024 * 1024,
  });

  assert.equal(plan.runtimeCommand, "docker");
  assert.equal(plan.enforcedControls.networkPolicy, "none");
  assert.equal(plan.enforcedControls.repositoryReadOnly, true);
  assert.equal(plan.enforcedControls.rootFilesystemReadOnly, true);
  assert.equal(plan.enforcedControls.scratchSeparated, true);
  assert.equal(plan.enforcedControls.runAsNonRoot, true);
  assert.equal(plan.enforcedControls.capabilitiesDropped, true);
  assert.equal(plan.enforcedControls.allowPrivilegeEscalation, false);
  assert.equal(plan.enforcedControls.hostSocketMounts, false);
  assert.ok(plan.runtimeArgs.includes("--pull=never"));
  assert.ok(plan.runtimeArgs.includes("--network=none"));
  assert.ok(plan.runtimeArgs.includes("--ipc=none"));
  assert.ok(plan.runtimeArgs.includes("--read-only"));
  assert.ok(plan.runtimeArgs.includes("--cap-drop=ALL"));
  assert.ok(plan.runtimeArgs.includes("--security-opt=no-new-privileges=true"));
  assert.ok(plan.runtimeArgs.includes("--pids-limit=128"));
  assert.ok(plan.runtimeArgs.includes("--memory=536870912"));
  assert.ok(plan.runtimeArgs.includes("--memory-swap=536870912"));
  assert.ok(plan.runtimeArgs.includes("--cpus=1.5"));
  assert.ok(plan.runtimeArgs.includes("--user=65532:65532"));
  assert.ok(plan.runtimeArgs.includes("type=bind,src=/srv/synsec/workspaces/job-1,dst=/workspace,readonly"));
  assert.ok(plan.runtimeArgs.includes("--tmpfs"));
  assert.ok(plan.runtimeArgs.includes("/scratch:rw,noexec,nosuid,nodev,size=67108864,uid=65532,gid=65532,mode=0700"));
  assert.ok(plan.runtimeArgs.includes("/tmp:rw,noexec,nosuid,nodev,size=67108864,uid=65532,gid=65532,mode=0700"));
  assert.equal(plan.runtimeArgs.includes("--privileged"), false);
  assert.equal(plan.runtimeArgs.some((value) => value.includes("docker.sock")), false);
});

test("OCI scanner plan rejects mutable images, root users, unsafe mounts, and unbounded resources", () => {
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: "scanner:latest", repositoryRoot: "/repo" }),
    /pinned by sha256 digest/,
  );
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: fixtureImage, repositoryRoot: "repo" }),
    /absolute mount-safe path/,
  );
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: fixtureImage, repositoryRoot: "/repo,escape" }),
    /absolute mount-safe path/,
  );
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: fixtureImage, repositoryRoot: "/repo", runAsUser: "0:0" }),
    /non-root/,
  );
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: fixtureImage, repositoryRoot: "/repo", pidsLimit: 1 }),
    /PID limit/,
  );
  assert.throws(
    () => buildOciScannerSandboxPlan("scanner", [], { image: fixtureImage, repositoryRoot: "/repo", memoryBytes: 1 }),
    /memory limit/,
  );
});

integration("OCI scanner execution actually observes read-only source, writable scratch, no credentials, and no network interface", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-oci-sandbox-"));
  const previousToken = process.env.GITHUB_TOKEN;
  try {
    await chmod(root, 0o755);
    await writeFile(join(root, "fixture.txt"), "repository evidence\n", { mode: 0o644 });
    process.env.GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const output = await runOciSandboxedScanner(
      "/bin/sh",
      [
        "-c",
        [
          "test -r /workspace/fixture.txt",
          "! touch /workspace/should-not-write",
          "touch /scratch/write-ok",
          "touch /tmp/write-ok",
          "test \"$(id -u)\" -ne 0",
          "test -z \"${GITHUB_TOKEN:-}\"",
          "test ! -e /var/run/docker.sock",
          "! grep -q 'eth0:' /proc/net/dev",
        ].join(" && "),
      ],
      {
        image: digestImage,
        repositoryRoot: root,
        cpuLimit: 0.5,
        memoryBytes: 128 * 1024 * 1024,
        pidsLimit: 32,
        scratchBytes: 32 * 1024 * 1024,
        timeoutMs: 30_000,
        maxOutputBytes: 1024 * 1024,
      },
    );
    assert.equal(output.exitCode, 0, output.stderr);
    assert.doesNotMatch(`${output.stdout}\n${output.stderr}`, /ghp_abcdefghijklmnopqrstuvwxyz1234567890/);
  } finally {
    if (previousToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = previousToken;
    await rm(root, { recursive: true, force: true });
  }
});
