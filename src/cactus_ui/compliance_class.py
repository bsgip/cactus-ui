from dataclasses import dataclass


@dataclass
class ComplianceClass:
    name: str
    description: str


# This is an adapted version of TS 5573 Table 12.5 - Applicability of tests to classes of DER client
COMPLIANCE_CLASS_ORDERED: list[tuple[str, ComplianceClass]] = [
    ("A", ComplianceClass("A", "All clients managing DER (Excluding demand response).")),
    ("G", ComplianceClass("G", "Clients managing generation-type or storage-type DER.")),
    ("L", ComplianceClass("L", "Clients managing load-type or storage-type DER.")),
    ("C", ComplianceClass("C", "Clients conforming with the optional ConnectionPoint extension.")),
    ("S", ComplianceClass("S", "Clients implementing Subscription/Notification functionality.")),
    ("M", ComplianceClass("M", "Clients supporting management of sets of DER.")),
    ("DER-A", ComplianceClass("DER-A", "All DER.")),
    ("DER-G", ComplianceClass("DER-G", "All DER capable of generation.")),
    ("DER-L", ComplianceClass("DER-L", "All DER capable of consumption.")),
    ("DR-A", ComplianceClass("DR-A", "All clients managing demand response devices.")),
    ("DR-D", ComplianceClass("DR-D", "Clients managing or incorporated into DRED demand response devices.")),
    (
        "DR-L",
        ComplianceClass(
            "DR-L", "Clients managing load-type or storage-type products with demand response capabilities."
        ),
    ),
    (
        "DR-G",
        ComplianceClass(
            "DR-G", "Clients managing generation-type or storage-type products with demand response capabilities."
        ),
    ),
]


def fetch_compliance_classes(class_names: set[str]) -> list[ComplianceClass]:
    items: list[ComplianceClass] = []
    matched_keys: set[str] = set()

    for key, cc in COMPLIANCE_CLASS_ORDERED:
        if key in class_names:
            items.append(cc)
            matched_keys.add(key)

    # Now find anything leftover in class_names that we don't have a description for
    for class_name in class_names:
        if class_name not in matched_keys:
            items.append(ComplianceClass(class_name, ""))

    return items
