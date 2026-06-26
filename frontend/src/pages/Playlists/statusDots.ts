import type { PlaylistTestStatus } from '../../api/types';

export type DotKind = 'success' | 'failed' | 'pending' | 'active' | 'skipped';

export const DOT_COLOR: Record<DotKind, string> = {
  success: 'var(--green-9)',
  failed: 'var(--red-9)',
  pending: 'var(--gray-7)',
  active: 'var(--blue-9)',
  skipped: 'var(--gray-9)',
};

// Returns the ordered status dots plus the run the playlist is currently sitting on
// (first active/initialised run), used for "Go to run".
export function statusDots(testStatuses: PlaylistTestStatus[]): {
  dots: { kind: DotKind; title: string }[];
  activeRunId: number | null;
} {
  const dots: { kind: DotKind; title: string }[] = [];
  let activeRunId: number | null = null;

  for (const ts of testStatuses) {
    let kind: DotKind = 'pending';
    let title = `${ts.test_procedure_id}: Queued`;
    if (ts.all_criteria_met === true) {
      kind = 'success';
      title = `${ts.test_procedure_id}: Passed`;
    } else if (ts.all_criteria_met === false) {
      kind = 'failed';
      title = `${ts.test_procedure_id}: Failed`;
    } else if (ts.status === 'skipped') {
      kind = 'skipped';
      title = `${ts.test_procedure_id}: Skipped`;
    } else if (ts.status === 'started' || ts.status === 'provisioning') {
      kind = 'active';
      title = `${ts.test_procedure_id}: Running`;
      if (activeRunId === null) {
        activeRunId = ts.run_id;
      }
    } else if (ts.status === 'initialised') {
      if (activeRunId === null) {
        activeRunId = ts.run_id;
      }
    }
    dots.push({ kind, title });
  }

  return { dots, activeRunId };
}
