"""Presenters: pure transforms from orchestrator schema objects to the plain JSON dicts
the SPA consumes. No Flask, no request context, no I/O — directly unit-testable.

This is the data-assembly logic the migration kept in Python (category grouping,
compliance-by-class, pagination shaping, playlist test lists).
"""

from collections import defaultdict

import cactus_schema.orchestrator as schema
from cactus_schema.orchestrator.compliance import fetch_compliance_classes

_ACTIVE_RUN_STATUS_INTS = [1, 2, 6]  # initialised, started, provisioning
_FINALIZED_RUN_STATUS_INTS = [3, 4]  # finalised by user, finalised by timeout


def run_summary_to_compliance_status(
    test_procedure: schema.TestProcedureRunSummaryResponse,
) -> str:
    if test_procedure.latest_run_status in _ACTIVE_RUN_STATUS_INTS:
        return "active"
    elif test_procedure.run_count == 0:
        return "runless"
    elif test_procedure.latest_run_status in _FINALIZED_RUN_STATUS_INTS:
        if test_procedure.latest_all_criteria_met:
            return "success"
        else:
            return "failed"
    else:
        return "unknown"


def build_playlist_tests_by_category(
    procedures: list[schema.TestProcedureRunSummaryResponse],
) -> dict[str, list[dict]]:
    """Build ordered category→tests dict for the playlist builder, excluding immediate_start procedures.

    Procedures are expected to arrive in definition order from the orchestrator; insertion order is preserved.
    """
    result: dict[str, list[dict]] = {}
    for p in procedures:
        if p.immediate_start:
            continue
        cat = p.category
        if cat not in result:
            result[cat] = []
        result[cat].append(
            {
                "id": str(p.test_procedure_id),
                "description": p.description,
                "classes": p.classes or [],
            }
        )
    return result


def build_test_status_dict(run: schema.RunResponse) -> dict:
    """Build a test status dictionary from a RunResponse for playlist display."""
    return {
        "test_procedure_id": run.test_procedure_id,
        "run_id": run.run_id,
        "status": run.status.value if hasattr(run.status, "value") else str(run.status),
        "all_criteria_met": run.all_criteria_met,
        "has_artifacts": run.has_artifacts,
    }


def paginated_json(page: schema.Pagination) -> dict:
    """Serialise a Pagination of JSONWizard items to a plain dict (snake_case keys, ISO datetimes)."""
    return {
        "total_pages": page.total_pages,
        "total_items": page.total_items,
        "page_size": page.page_size,
        "current_page": page.current_page,
        "prev_page": page.prev_page,
        "next_page": page.next_page,
        "items": [item.to_dict() for item in page.items],
    }


def build_procedure_summaries_json(procedures: list[schema.TestProcedureRunSummaryResponse]) -> dict:
    """Groups procedure run summaries by category (preserving order) with compliance class filter maps."""
    grouped: dict[str, dict] = {}  # slug -> group, insertion ordered
    all_classes: set[str] = set()
    classes_by_test: dict[str, list[str]] = {}
    classes_by_category: dict[str, set[str]] = {}

    for p in procedures:
        category_slug = p.category.replace(" ", "-")  # This could do with a more robust slugify method

        group = grouped.setdefault(category_slug, {"slug": category_slug, "category": p.category, "summaries": []})
        group["summaries"].append(p.to_dict())

        classes = p.classes if p.classes else []
        classes_by_test[p.test_procedure_id] = classes
        all_classes.update(classes)
        classes_by_category.setdefault(category_slug, set()).update(classes)

    return {
        "grouped_procedures": list(grouped.values()),
        "classes": [{"name": c.name, "description": c.description} for c in fetch_compliance_classes(all_classes)],
        "classes_by_test": classes_by_test,
        "classes_by_category": {key: sorted(value) for key, value in classes_by_category.items()},
    }


def build_compliance_json(procedures: list[schema.TestProcedureRunSummaryResponse]) -> dict:
    """Compute compliance-by-class from procedure run summaries."""
    tests_by_class: dict[str, list[str]] = defaultdict(list)
    for p in procedures:
        if p.classes:
            for c in p.classes:
                tests_by_class[c].append(str(p.test_procedure_id))

    procedure_map: dict[str, schema.TestProcedureRunSummaryResponse] = {str(p.test_procedure_id): p for p in procedures}
    result = []
    for compliance_class, tests in tests_by_class.items():
        per_run_status = [
            {
                "test_procedure_id": t,
                "description": procedure_map[t].description,
                "latest_run_id": procedure_map[t].latest_run_id,
                "status": run_summary_to_compliance_status(procedure_map[t]),
            }
            for t in tests
        ]
        compliant = all(r["status"] == "success" for r in per_run_status)
        matched_classes = fetch_compliance_classes({compliance_class})
        class_details = matched_classes[0] if matched_classes else None
        result.append(
            {
                "class_name": compliance_class,
                "class_details": {
                    "name": class_details.name,
                    "description": class_details.description,
                }
                if class_details
                else {"name": compliance_class, "description": ""},
                "compliant": compliant,
                "per_run_status": per_run_status,
            }
        )
    return {"compliance_by_class": result}
