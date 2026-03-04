#!/usr/bin/env python3
"""
Populate TestData/ with realistic folder structure and file content
for encryption/decryption testing. Run from repo root.

Usage:
  python populate_testdata.py

Removes existing TestData content and creates:
  - Documents/ (notes, drafts, meeting notes)
  - Finance/ (invoices, budgets, expense CSVs with many rows)
  - Projects/ (code snippets, configs, READMEs)
  - Notes/ (markdown, todos)
  - Backup/ (larger text dumps)
"""

import random
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
TESTDATA = REPO_ROOT / "TestData"

# Lorem-style paragraphs for realistic text
PARAS = [
    "The project timeline has been adjusted to account for the integration phase. "
    "Stakeholders will receive an updated Gantt chart by end of week. "
    "Please ensure all dependencies are documented in the shared drive.",
    "Quarterly review meeting scheduled for next Tuesday at 2 PM. "
    "Agenda items include budget variance analysis, hiring plan, and Q4 objectives. "
    "Action items from last meeting are still pending from Engineering.",
    "Expense report submitted for reimbursement. Receipts attached. "
    "Total amount reflects travel to the regional conference and client dinners. "
    "Per diem was within policy guidelines.",
    "The new backup procedure runs nightly at 02:00. Retention is 30 days for incremental "
    "and 12 months for full backups. Verify restore was tested last quarter.",
    "User acceptance testing for the portal is scheduled to begin Monday. "
    "Test accounts have been provisioned. Please log any issues in JIRA under PROJECT-UT. "
    "Sign-off is required before production deployment.",
]


def random_paragraphs(n=5):
    return "\n\n".join(random.choices(PARAS, k=n))


def random_csv_rows(rows=50):
    """Generate CSV with header and many data rows."""
    lines = ["Date,Category,Vendor,Amount,Notes"]
    categories = ["Travel", "Software", "Meals", "Supplies", "Training", "Hardware"]
    vendors = ["Acme Corp", "Office Depot", "AWS", "Restaurant Group", "TechTrain Inc"]
    for _ in range(rows):
        date = f"2025-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        cat = random.choice(categories)
        vendor = random.choice(vendors)
        amount = round(random.uniform(10, 2500), 2)
        notes = random.choice(["", "Paid", "Pending", "Reimbursable"])
        lines.append(f"{date},{cat},{vendor},{amount},{notes}")
    return "\n".join(lines)


def main():
    if TESTDATA.exists():
        for p in TESTDATA.iterdir():
            if p.is_file():
                p.unlink()
            else:
                shutil.rmtree(p)
    else:
        TESTDATA.mkdir(parents=True)

    # Documents: meeting notes, drafts
    docs = TESTDATA / "Documents"
    docs.mkdir()
    for i in range(15):
        (docs / f"meeting_notes_2025_{i+1:02d}.txt").write_text(
            random_paragraphs(random.randint(6, 12)), encoding="utf-8"
        )
    for i in range(12):
        (docs / f"draft_proposal_v{i+1}.txt").write_text(
            random_paragraphs(15), encoding="utf-8"
        )

    # Finance: invoices and budgets (CSV with many rows)
    finance = TESTDATA / "Finance"
    budgets = finance / "Budgets"
    invoices = finance / "Invoices"
    budgets.mkdir(parents=True)
    invoices.mkdir(parents=True)
    for i in range(25):
        (budgets / f"expense_report_{i:04d}.csv").write_text(
            random_csv_rows(random.randint(150, 400)), encoding="utf-8"
        )
    for i in range(20):
        (invoices / f"invoice_{i:04d}.csv").write_text(
            random_csv_rows(random.randint(80, 200)), encoding="utf-8"
        )
    (finance / "annual_summary.txt").write_text(random_paragraphs(35), encoding="utf-8")

    # Projects: code and configs
    projects = TESTDATA / "Projects"
    proj_a = projects / "project_alpha"
    proj_b = projects / "project_beta"
    proj_a.mkdir(parents=True)
    proj_b.mkdir(parents=True)
    (proj_a / "README.md").write_text(
        "# Project Alpha\n\n" + random_paragraphs(4) + "\n\n## Setup\n\nRun `pip install -r requirements.txt`.\n",
        encoding="utf-8",
    )
    (proj_a / "config.json").write_text(
        '{"env": "development", "debug": true, "database": {"host": "localhost", "port": 5432}}\n',
        encoding="utf-8",
    )
    (proj_a / "main.py").write_text(
        '"""Entry point for Project Alpha."""\nimport sys\n\ndef main():\n    print("Hello")\n\nif __name__ == "__main__":\n    main()\n',
        encoding="utf-8",
    )
    (proj_b / "README.md").write_text(
        "# Project Beta\n\n" + random_paragraphs(6), encoding="utf-8"
    )
    (proj_b / "settings.yaml").write_text(
        "version: 1\nlog_level: info\nfeatures:\n  auth: true\n  cache: true\n",
        encoding="utf-8",
    )

    # Notes: markdown and todos
    notes = TESTDATA / "Notes"
    notes.mkdir()
    (notes / "todo.md").write_text(
        "- [ ] Review pull request #42\n- [ ] Update documentation\n- [ ] Schedule demo\n" * 25,
        encoding="utf-8",
    )
    for i in range(18):
        (notes / f"note_{i}.md").write_text(
            f"# Note {i}\n\n" + random_paragraphs(random.randint(5, 12)),
            encoding="utf-8",
        )

    # Backup: larger text files to make the archive feel substantial (~200MB total)
    backup = TESTDATA / "Backup"
    backup.mkdir()
    chunk = random_paragraphs(20) + "\n"
    for i in range(100):
        (backup / f"export_{i}.txt").write_text(chunk * 500, encoding="utf-8")

    total_files = sum(1 for _ in TESTDATA.rglob("*") if _.is_file())
    total_size = sum(f.stat().st_size for f in TESTDATA.rglob("*") if f.is_file())
    print(f"Created {total_files} files in {TESTDATA} ({total_size / (1024*1024):.1f} MB)")


if __name__ == "__main__":
    main()
