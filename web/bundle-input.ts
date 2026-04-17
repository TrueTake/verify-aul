/**
 * Drop-zone wiring for the verifier UI.
 *
 * Accepts a JSON file via file picker, drag-drop, or keyboard (space/enter
 * on the focused drop zone). Size-guard + JSON-parse-guard enforce
 * boundaries before the bundle reaches the verifier.
 */

import type { VerificationBundle } from '@truetake/verify-aul';

const MAX_BYTES = 10 * 1024 * 1024; // 10 MB

export interface BundleInputHandler {
  onBundle: (bundle: VerificationBundle) => void;
  onError: (message: string) => void;
}

export function wireBundleInput(handler: BundleInputHandler): void {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input') as HTMLInputElement | null;

  if (!dropZone || !fileInput) {
    return;
  }

  // Click & keyboard open
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInput.click();
    }
  });

  // Drag visual feedback
  dropZone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropZone.dataset['dragOver'] = 'true';
  });
  dropZone.addEventListener('dragleave', () => {
    delete dropZone.dataset['dragOver'];
  });

  dropZone.addEventListener('drop', (event) => {
    event.preventDefault();
    delete dropZone.dataset['dragOver'];
    const file = event.dataTransfer?.files[0];
    if (file) {
      void handleFile(file, handler, dropZone);
    }
  });

  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (file) {
      void handleFile(file, handler, dropZone);
    }
  });
}

async function handleFile(
  file: File,
  handler: BundleInputHandler,
  dropZone: HTMLElement,
): Promise<void> {
  dropZone.setAttribute('aria-invalid', 'false');

  if (file.size > MAX_BYTES) {
    dropZone.setAttribute('aria-invalid', 'true');
    handler.onError(`File too large: ${formatBytes(file.size)} > 10 MB cap`);
    return;
  }

  let raw: string;
  try {
    raw = await file.text();
  } catch (err) {
    dropZone.setAttribute('aria-invalid', 'true');
    handler.onError(`Could not read file: ${errMsg(err)}`);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    dropZone.setAttribute('aria-invalid', 'true');
    handler.onError(`Invalid JSON: ${errMsg(err)}`);
    return;
  }

  if (typeof parsed !== 'object' || parsed === null) {
    dropZone.setAttribute('aria-invalid', 'true');
    handler.onError('Bundle must be a JSON object.');
    return;
  }

  handler.onBundle(parsed as VerificationBundle);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
