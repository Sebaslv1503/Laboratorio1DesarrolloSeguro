import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd

from vulnminer.catalog import API_2023, OWASP_2025
from vulnminer.scanner import evidence_for, scan


class VULNMINERTests(unittest.TestCase):
    def test_full_catalogs(self):
        self.assertEqual(len(OWASP_2025), 10)
        self.assertEqual(len(API_2023), 10)

    def test_sample_minimums_multilanguage_and_traceability(self):
        data = pd.read_csv(ROOT / "data/vulnerabilities.csv")
        self.assertGreaterEqual(len(data), 500)
        self.assertGreaterEqual((data.label == "safe").sum(), 100)
        self.assertTrue(data.synthetic.notna().all())
        non_synth = data[~data.synthetic.astype(str).str.lower().isin(["true", "1"])]
        lang_counts = non_synth["language"].value_counts()
        substantial_langs = [lang for lang, n in lang_counts.items() if lang in {"Java", "Python", "JavaScript", "TypeScript"} and n >= 50]
        self.assertGreaterEqual(len(substantial_langs), 2)

    def test_evaluated_coverage_meets_pdf_minimums(self):
        assessment = json.loads((ROOT / "reports/assessment.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(assessment["evaluated_owasp"]), 5)
        self.assertGreaterEqual(len(assessment["evaluated_api"]), 4)
        self.assertEqual(
            set(assessment["evaluated_owasp"]) | set(assessment["not_evaluated_owasp"]),
            set(OWASP_2025),
        )
        self.assertEqual(
            set(assessment["evaluated_api"]) | set(assessment["not_evaluated_api"]),
            set(API_2023),
        )

    def test_evidence_reports_line_and_cwe(self):
        code = "def get():\n    return os.system(request.args['cmd'])\n"
        evidence = evidence_for(code)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence[0], 2)
        self.assertEqual(evidence[2], 78)

    def test_demo_scan_finds_services_and_candidates(self):
        report = scan(ROOT / "examples/demo-microservices", ROOT / "models/vulnminer.joblib")
        self.assertGreaterEqual(report["summary"]["microservices"], 2)
        self.assertEqual(report["summary"]["files_analyzed"], 4)
        self.assertGreater(report["summary"]["potential_findings"], 0)
        self.assertIn("category_coverage", report)
        self.assertTrue(
            all(
                item["status"].endswith("review_required")
                or item["status"] == "requires_manual_review"
                for item in report["findings"]
            )
        )


if __name__ == "__main__":
    unittest.main()
