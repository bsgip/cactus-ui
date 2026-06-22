"""Presenters: pure transforms from orchestrator schema objects to the BFF response
dataclasses the SPA consumes (see cactus_ui.api_models). No Flask, no request context, no
I/O — directly unit-testable.

This is the data-assembly logic the migration kept in Python (category grouping,
compliance-by-class, pagination shaping, playlist test lists). Returning the typed dataclasses
(rather than raw dicts) keeps the wire format tied to the generated TS types.
"""

from collections import defaultdict

import cactus_schema.orchestrator as schema
from cactus_schema.orchestrator.compliance import ComplianceClass, fetch_compliance_classes

from cactus_ui.api_models import (
    ComplianceClassEntry,
    ComplianceResponse,
    ComplianceStatus,
    GroupedProcedures,
    PerRunStatus,
    PlaylistTest,
    PlaylistTestStatus,
    ProcedureSummariesResponse,
)

_ACTIVE_RUN_STATUS_INTS = [1, 2, 6]  # initialised, started, provisioning
_FINALIZED_RUN_STATUS_INTS = [3, 4]  # finalised by user, finalised by timeout


def run_summary_to_compliance_status(
    test_procedure: schema.TestProcedureRunSummaryResponse,
) -> ComplianceStatus:
    if test_procedure.latest_run_status in _ACTIVE_RUN_STATUS_INTS:
        return ComplianceStatus.active
    elif test_procedure.run_count == 0:
        return ComplianceStatus.runless
    elif test_procedure.latest_run_status in _FINALIZED_RUN_STATUS_INTS:
        if test_procedure.latest_all_criteria_met:
            return ComplianceStatus.success
        else:
            return ComplianceStatus.failed
    else:
        return ComplianceStatus.unknown


def build_playlist_tests_by_category(
    procedures: list[schema.TestProcedureRunSummaryResponse],
) -> dict[str, list[PlaylistTest]]:
    """Build ordered category→tests dict for the playlist builder, excluding immediate_start procedures.

    Procedures are expected to arrive in definition order from the orchestrator; insertion order is preserved.
    """
    result: dict[str, list[PlaylistTest]] = {}
    for p in procedures:
        if p.immediate_start:
            continue
        result.setdefault(p.category, []).append(
            PlaylistTest(id=str(p.test_procedure_id), description=p.description, classes=p.classes or [])
        )
    return result


def build_test_status(run: schema.RunResponse) -> PlaylistTestStatus:
    """Build a test status entry from a RunResponse for playlist display."""
    return PlaylistTestStatus(
        test_procedure_id=run.test_procedure_id,
        run_id=run.run_id,
        status=run.status,
        all_criteria_met=run.all_criteria_met,
        has_artifacts=run.has_artifacts,
    )


def paginated_json(page: schema.Pagination) -> dict:
    """Serialise a Pagination of JSONWizard items to a plain dict (snake_case keys, ISO datetimes).

    Pagination is the one wire shape kept hand-written (a generic) on the frontend, so it stays
    a dict here rather than a generated dataclass.
    """
    return {
        "total_pages": page.total_pages,
        "total_items": page.total_items,
        "page_size": page.page_size,
        "current_page": page.current_page,
        "prev_page": page.prev_page,
        "next_page": page.next_page,
        "items": [item.to_dict() for item in page.items],
    }


def build_procedure_summaries(
    procedures: list[schema.TestProcedureRunSummaryResponse],
) -> ProcedureSummariesResponse:
    """Groups procedure run summaries by category (preserving order) with compliance class filter maps."""
    grouped: dict[str, GroupedProcedures] = {}  # slug -> group, insertion ordered
    all_classes: set[str] = set()
    classes_by_test: dict[str, list[str]] = {}
    classes_by_category: dict[str, set[str]] = {}

    for p in procedures:
        category_slug = p.category.replace(" ", "-")  # This could do with a more robust slugify method

        group = grouped.setdefault(
            category_slug, GroupedProcedures(slug=category_slug, category=p.category, summaries=[])
        )
        group.summaries.append(p)

        classes = p.classes if p.classes else []
        classes_by_test[p.test_procedure_id] = classes
        all_classes.update(classes)
        classes_by_category.setdefault(category_slug, set()).update(classes)

    return ProcedureSummariesResponse(
        grouped_procedures=list(grouped.values()),
        classes=list(fetch_compliance_classes(all_classes)),
        classes_by_test=classes_by_test,
        classes_by_category={key: sorted(value) for key, value in classes_by_category.items()},
    )


def build_compliance(procedures: list[schema.TestProcedureRunSummaryResponse]) -> ComplianceResponse:
    """Compute compliance-by-class from procedure run summaries."""
    tests_by_class: dict[str, list[str]] = defaultdict(list)
    for p in procedures:
        if p.classes:
            for c in p.classes:
                tests_by_class[c].append(str(p.test_procedure_id))

    procedure_map: dict[str, schema.TestProcedureRunSummaryResponse] = {str(p.test_procedure_id): p for p in procedures}
    compliance_by_class = []
    for compliance_class, tests in tests_by_class.items():
        per_run_status = [
            PerRunStatus(
                test_procedure_id=t,
                description=procedure_map[t].description,
                latest_run_id=procedure_map[t].latest_run_id,
                status=run_summary_to_compliance_status(procedure_map[t]),
            )
            for t in tests
        ]
        compliant = all(r.status == ComplianceStatus.success for r in per_run_status)
        matched_classes = fetch_compliance_classes({compliance_class})
        class_details = (
            matched_classes[0] if matched_classes else ComplianceClass(name=compliance_class, description="")
        )
        compliance_by_class.append(
            ComplianceClassEntry(
                class_name=compliance_class,
                class_details=class_details,
                compliant=compliant,
                per_run_status=per_run_status,
            )
        )
    return ComplianceResponse(compliance_by_class=compliance_by_class)
