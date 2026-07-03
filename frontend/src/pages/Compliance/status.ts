// Compliance-request status helpers, shared by the list page and the request wizard.
// Mirrors cactus_ui.orchestrator.ComplianceRequestStatus (a 1-indexed IntEnum).

export const ComplianceStatus = {
  SUBMITTED: 1,
  UNDER_REVIEW: 2,
  PUSHED_BACK: 3,
  FINALISED: 4,
} as const;

export type ComplianceAction = 'edit' | 'view' | 'download' | 'delete';

// Human-readable status, worded differently for the admin (reviewer) and user (submitter).
export function statusLabel(status: number, isAdminView: boolean): string {
  switch (status) {
    case ComplianceStatus.SUBMITTED:
      return isAdminView ? 'Awaiting Review' : 'Submitted';
    case ComplianceStatus.UNDER_REVIEW:
      return 'Under Review';
    case ComplianceStatus.PUSHED_BACK:
      return isAdminView ? 'Waiting on User Amendments' : 'Changes Requested';
    case ComplianceStatus.FINALISED:
      return 'Finalised';
    default:
      return `Unknown status: ${status}`;
  }
}

// Which row actions are offered, by status and viewer.
export function actionsForStatus(status: number, isAdminView: boolean): ComplianceAction[] {
  switch (status) {
    case ComplianceStatus.SUBMITTED:
      return isAdminView ? ['edit'] : ['edit', 'delete'];
    case ComplianceStatus.UNDER_REVIEW:
      return isAdminView ? ['edit'] : ['view'];
    case ComplianceStatus.PUSHED_BACK:
      return isAdminView ? ['view'] : ['edit', 'delete'];
    case ComplianceStatus.FINALISED:
      return isAdminView ? ['download'] : ['view'];
    default:
      return [];
  }
}
