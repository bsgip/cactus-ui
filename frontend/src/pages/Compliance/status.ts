// Compliance-request status helpers, shared by the list page and the request wizard.
// Mirrors cactus_ui.orchestrator.ComplianceRequestStatus (a 1-indexed IntEnum).

export const ComplianceStatus = {
  SUBMITTED: 1,
  UNDER_REVIEW: 2,
  PUSHED_BACK: 3,
  FINALISED: 4,
} as const;

export type ComplianceAction = 'edit' | 'view' | 'download' | 'delete';

