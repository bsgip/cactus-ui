from cactus_schema.orchestrator.compliance import ComplianceClass, fetch_compliance_classes


def fetch_compliance_class(class_name: str) -> ComplianceClass | None:
    classes = fetch_compliance_classes({class_name})
    if classes:
        return classes[0]
    return None
