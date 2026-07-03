import type { PlaylistTestStatus } from '../../api/types';
import type { ResultKind } from '../../utils/status';

// Returns the ordered status dots plus the run the playlist is currently sitting on
// (first active/initialised run), used for "Go to run".
export function statusDots(testStatuses: PlaylistTestStatus[]): {
  dots: { kind: ResultKind; title: string }[];
  activeRunId: number | null;
} {
  const dots: { kind: ResultKind; title: string }[] = [];
  let activeRunId: number | null = null;

  for (const ts of testStatuses) {
    let kind: ResultKind = 'pending';
    let title = `${ts.test_procedure_id}: Queued`;
    if (ts.all_criteria_met === true) {
      kind = 'pass';
      title = `${ts.test_procedure_id}: Passed`;
    } else if (ts.all_criteria_met === false) {
      kind = 'fail';
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
