// Semantic colors for run/test results. Kept explicit (not the theme accent) so a result's
// meaning stays stable regardless of the brand color. Shared by the runs table and the
// playlist status dots.
export type ResultKind = 'pass' | 'fail' | 'active' | 'pending' | 'skipped';

// Solid color for result icons and status dots.
export const RESULT_COLOR: Record<ResultKind, string> = {
  pass: 'var(--green-9)',
  fail: 'var(--red-9)',
  active: 'var(--blue-9)',
  pending: 'var(--gray-7)',
  skipped: 'var(--gray-9)',
};

// Soft background tint for highlighted table rows (omitted kinds get no tint).
export const RESULT_TINT: Partial<Record<ResultKind, string>> = {
  pass: 'var(--green-2)',
  fail: 'var(--red-2)',
  active: 'var(--blue-2)',
};
