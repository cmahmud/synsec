#!/usr/bin/env node

import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { readLifecycleStore } from "@synsec/lifecycle";
import {
  assessLifecycleReviewDeadlines,
  type LifecycleReviewDeadlineAssessment,
} from "@synsec/lifecycle/review-deadlines";

const MAX_INPUT_BYTES = 1024 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;
const args = process.argv.slice(2);

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1];
  const prefix = `${name}=`;
  const inline = args.find((value) => value.startsWith(prefix));
  return inline?.slice(prefix.length);
}

function flag(name: string): boolean {
  return args.includes(name);
}

function validateArguments(): void {
  const supportedFlags = new Set([
    "--json",
    "--fail-overdue",
    "--fail-unscheduled",
  ]);
  const supportedOptions = new Set(["--now", "--due-soon-days"]);

  for (let index = 1; index < args.length; index += 1) {
    const value = args[index];
    if (!value?.startsWith("--")) continue;
    const name = value.includes("=") ? value.slice(0, value.indexOf("=")) : value;
    if (supportedFlags.has(name)) continue;
    if (supportedOptions.has(name)) {
      if (!value.includes("=")) index += 1;
      continue;
    }
    throw new Error("Unsupported lifecycle review option.");
  }
}

function dueSoonWindowMs(): number | undefined {
  const raw = option("--due-soon-days");
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw)) throw new Error("--due-soon-days must be an integer between 0 and 365.");
  const days = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(days) || days < 0 || days > 365) {
    throw new Error("--due-soon-days must be an integer between 0 and 365.");
  }
  return days * DAY_MS;
}

function renderText(path: string, assessment: LifecycleReviewDeadlineAssessment): string[] {
  const lines = [
    `Lifecycle store: ${path}`,
    `Reviewable exceptions: ${assessment.summary.reviewable}`,
    `Overdue: ${assessment.summary.overdue}`,
    `Due soon: ${assessment.summary.dueSoon}`,
    `Scheduled: ${assessment.summary.scheduled}`,
    `Unscheduled: ${assessment.summary.unscheduled}`,
  ];
  for (const item of assessment.items) {
    lines.push(`[${item.status.toUpperCase()}] ${item.fingerprint}  ${item.state}  ${item.reviewAt}`);
  }
  return lines;
}

async function main(): Promise<void> {
  validateArguments();
  const input = args[0];
  if (!input || input.startsWith("--")) {
    throw new Error("Usage: synsec-lifecycle-reviews <lifecycle.json> [--now <timestamp>] [--due-soon-days <0-365>] [--json] [--fail-overdue] [--fail-unscheduled]");
  }

  const path = resolve(input);
  const info = await stat(path);
  if (!info.isFile()) throw new Error("Lifecycle review input must be a regular file.");
  if (info.size > MAX_INPUT_BYTES) throw new Error(`Lifecycle review input exceeds ${MAX_INPUT_BYTES} bytes.`);

  const store = await readLifecycleStore(path);
  const windowMs = dueSoonWindowMs();
  const assessment = assessLifecycleReviewDeadlines(store, {
    now: option("--now"),
    ...(windowMs === undefined ? {} : { dueSoonWindowMs: windowMs }),
  });

  if (flag("--json")) process.stdout.write(`${JSON.stringify(assessment, null, 2)}\n`);
  else for (const line of renderText(path, assessment)) console.log(line);

  if (flag("--fail-overdue") && assessment.summary.overdue > 0) process.exitCode = 2;
  else if (flag("--fail-unscheduled") && assessment.summary.unscheduled > 0) process.exitCode = 3;
}

main().catch((error: unknown) => {
  console.error(`SynSec lifecycle review error: ${error instanceof Error ? error.message : "unexpected failure"}`);
  process.exitCode = 1;
});
