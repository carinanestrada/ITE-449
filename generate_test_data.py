"""
Generate a realistic test data set for the ITE-449 folder encryption project.

This script creates ~20,000 fake business files under the `TestData` folder,
organized into multiple subfolders representing a small business.

Each folder gets files whose names and basic text contents match that area,
so when you run `encrypt_folder.py` against `TestData`, it looks like a
small business that has been hit by ransomware.

Usage:
    python generate_test_data.py
"""

from __future__ import annotations

import random
from datetime import date
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parent
TESTDATA_ROOT = BASE_DIR / "TestData"
TARGET_FILE_COUNT = 20_000


DEPARTMENT_STRUCTURE = {
    "HR": {
        "Employees": [
            ("employee_list", "csv"),
            ("performance_review", "txt"),
            ("benefits_enrollment", "txt"),
        ],
        "Policies": [
            ("code_of_conduct", "txt"),
            ("vacation_policy", "txt"),
            ("remote_work_policy", "txt"),
        ],
        "Recruiting": [
            ("candidate_resume", "txt"),
            ("interview_feedback", "txt"),
            ("job_posting", "txt"),
        ],
    },
    "Finance": {
        "Invoices": [
            ("invoice", "csv"),
            ("payment_receipt", "txt"),
            ("statement", "txt"),
        ],
        "Payroll": [
            ("payroll_register", "csv"),
            ("pay_stub", "txt"),
            ("tax_withholding", "txt"),
        ],
        "Budgets": [
            ("annual_budget", "xlsx"),
            ("quarterly_forecast", "xlsx"),
            ("expense_report", "csv"),
        ],
    },
    "Sales": {
        "Leads": [
            ("lead_list", "csv"),
            ("cold_call_notes", "txt"),
            ("email_campaign", "txt"),
        ],
        "Opportunities": [
            ("opportunity_pipeline", "xlsx"),
            ("proposal", "txt"),
            ("customer_meeting_notes", "txt"),
        ],
        "Quotes": [
            ("sales_quote", "pdf"),
            ("pricing_sheet", "xlsx"),
            ("discount_approval", "txt"),
        ],
    },
    "IT": {
        "Tickets": [
            ("ticket", "txt"),
            ("incident_report", "txt"),
            ("change_request", "txt"),
        ],
        "Inventory": [
            ("asset_inventory", "csv"),
            ("laptop_checkout", "txt"),
            ("software_licenses", "txt"),
        ],
        "Backups": [
            ("backup_log", "log"),
            ("backup_config", "txt"),
            ("restore_instructions", "txt"),
        ],
    },
    "Operations": {
        "Logistics": [
            ("shipment_schedule", "xlsx"),
            ("delivery_log", "log"),
            ("carrier_contract", "txt"),
        ],
        "Facilities": [
            ("maintenance_log", "log"),
            ("access_badge_list", "csv"),
            ("safety_inspection", "txt"),
        ],
        "Vendors": [
            ("vendor_list", "csv"),
            ("service_agreement", "txt"),
            ("renewal_notice", "txt"),
        ],
    },
}


def iter_file_templates() -> Iterable[tuple[Path, str, str]]:
    """
    Yield (folder_path, base_name, extension) for all defined templates.
    """
    for dept, subfolders in DEPARTMENT_STRUCTURE.items():
        for subfolder, templates in subfolders.items():
            folder = TESTDATA_ROOT / dept / subfolder
            for base_name, extension in templates:
                yield folder, base_name, extension


def make_file_content(
    dept: str,
    subfolder: str,
    base_name: str,
    index: int,
) -> str:
    """Return simple, relevant text content for a fake business file."""
    today = date.today().isoformat()
    header = f"{dept} / {subfolder} :: {base_name}_{index:05d}"
    lines = [
        header,
        "-" * len(header),
        f"Generated test data for ITE-449 on {today}.",
        "This is fake business data intended for a controlled ransomware",
        "simulation and encryption exercise only.",
        "",
        f"Department: {dept}",
        f"Folder: {subfolder}",
        f"Record ID: {index}",
    ]
    return "\n".join(lines) + "\n"


def generate_test_data() -> None:
    random.seed(449)
    TESTDATA_ROOT.mkdir(parents=True, exist_ok=True)

    templates = list(iter_file_templates())
    if not templates:
        raise SystemExit("No file templates defined.")

    total_created = 0
    template_count = len(templates)

    # Spread files roughly evenly across all template types.
    while total_created < TARGET_FILE_COUNT:
        folder, base_name, extension = templates[total_created % template_count]
        dept = folder.parent.name if folder.parent != TESTDATA_ROOT else "General"
        subfolder = folder.name

        folder.mkdir(parents=True, exist_ok=True)

        index = total_created + 1
        filename = f"{base_name}_{index:05d}.{extension}"
        file_path = folder / filename

        # Avoid accidental overwrite if re-run: adjust name if needed.
        suffix = 1
        while file_path.exists():
            filename = f"{base_name}_{index:05d}_{suffix}.{extension}"
            file_path = folder / filename
            suffix += 1

        if extension.lower() in {"txt", "csv", "log", "md"}:
            content = make_file_content(dept, subfolder, base_name, index)
            file_path.write_text(content, encoding="utf-8")
        else:
            # For "binary-like" extensions (xlsx, pdf) we still just write text,
            # but the extension makes the data set look more realistic.
            content = make_file_content(dept, subfolder, base_name, index)
            file_path.write_text(content, encoding="utf-8")

        total_created += 1

    print(f"Created {total_created} fake business files under {TESTDATA_ROOT}")


if __name__ == "__main__":
    generate_test_data()

