import type { CriteriaEntry, RequestEntry, RunnerStatus, StepEventStatus } from '../../api/types';

// Event status the cactus runner assigns to a step that is blocked waiting for the user to
// signal "proceed". Must match the runner string exactly.
export const PROCEED_EVENT_STATUS = 'Waiting on signal to proceed';

export type StepPhase = 'pending' | 'active' | 'resolved';

export function stepPhase(info: StepEventStatus): StepPhase {
  if (info.completed_at) return 'resolved';
  if (info.started_at) return 'active';
  return 'pending';
}

// `Nm Ns` / `Ns` elapsed label, matching the old formatTimeLabel.
export function formatTimeLabel(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return mins > 0 ? `${mins}m${secs}s` : `${secs}s`;
}

// True when any step is the active step blocked on a proceed signal.
export function isProceedStepActive(stepStatus: Record<string, StepEventStatus> | null): boolean {
  if (!stepStatus) return false;
  return Object.values(stepStatus).some(
    (info) =>
      info.event_status === PROCEED_EVENT_STATUS &&
      info.started_at !== null &&
      info.completed_at === null
  );
}

// First active step (started, not completed) and its 1-based position, for the status banner.
export function activeStep(
  stepStatus: Record<string, StepEventStatus> | null
): { name: string; index: number } | null {
  if (!stepStatus) return null;
  const entries = Object.entries(stepStatus);
  for (let i = 0; i < entries.length; i++) {
    const [name, info] = entries[i];
    if (info.started_at && !info.completed_at) return { name, index: i + 1 };
  }
  return null;
}

// Criteria list with the synthetic all-xsd-valid criterion appended (only when requests
// exist), mirroring the old handleNewStatus criteria assembly.
export function criteriaWithXsd(status: RunnerStatus): CriteriaEntry[] {
  const criteria = [...(status.criteria ?? [])];
  const requests = status.request_history ?? [];
  if (requests.length > 0) {
    const errorCount = requests.filter((r) => r.body_xml_errors.length > 0).length;
    const success = errorCount === 0;
    criteria.push({
      type: 'all-xsd-valid',
      success,
      details: success
        ? `All ${requests.length} request(s) passed XSD validation`
        : `${errorCount} of ${requests.length} request(s) have XSD validation errors`,
    });
  }
  return criteria;
}

// Requests that failed XSD validation, newest first, capped at 10 (old xsdTableBody).
export function xsdErrorRequests(requests: RequestEntry[]): RequestEntry[] {
  return requests
    .filter((r) => r.body_xml_errors.length > 0)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 10);
}
