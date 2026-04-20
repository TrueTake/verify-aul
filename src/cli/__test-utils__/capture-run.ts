/**
 * Shared helper for CLI handler tests. Mocks process.stdout/stderr/exit for
 * the duration of `fn`, captures writes, and returns exit code + output.
 *
 * Used by the bundle / proof / verify-field handler tests plus the
 * field-commitment end-to-end vector test.
 */

import { vi } from 'vitest';

export interface CaptureResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function captureRun(fn: () => Promise<void>): Promise<CaptureResult> {
  let stdoutOutput = '';
  let stderrOutput = '';
  let capturedExitCode = 0;

  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdoutOutput += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderrOutput += String(chunk);
    return true;
  });
  vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null) => {
    capturedExitCode = typeof code === 'number' ? code : 0;
    throw { __isExit: true, code: capturedExitCode };
  });

  try {
    await fn();
    capturedExitCode = 0;
  } catch (err) {
    if (err && typeof err === 'object' && '__isExit' in err) {
      capturedExitCode = (err as { __isExit: true; code: number }).code;
    } else {
      throw err;
    }
  } finally {
    vi.mocked(process.stdout.write).mockRestore();
    vi.mocked(process.stderr.write).mockRestore();
    vi.mocked(process.exit).mockRestore();
  }

  return { stdout: stdoutOutput, stderr: stderrOutput, exitCode: capturedExitCode };
}
