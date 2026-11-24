"""SEMMA Explore: estadísticas descriptivas y visualizaciones reproducibles."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]


def explore(dataset: Path = ROOT / "data/vulnerabilities.csv", reports: Path = ROOT / "reports") -> dict:
    data = pd.read_csv(dataset).fillna("")
    reports.mkdir(parents=True, exist_ok=True)
    non_synthetic = data[data["synthetic"].astype(str).str.lower().isin(["false", "0"])]
    public = non_synthetic[non_synthetic["provenance"] != "Dataset profesor (muestra deduplicada)"]
    stats = {
        "records": int(len(data)),
        "public_records": int(len(public)),
        "teacher_records": int((data["provenance"] == "Dataset profesor (muestra deduplicada)").sum()),
        "non_synthetic_records": int(len(non_synthetic)),
        "synthetic_records": int(data["synthetic"].astype(str).str.lower().isin(["true", "1"]).sum()),
        "duplicates_exact": int(data.duplicated(["code", "label", "cwe"]).sum()),
        "missing_code": int(data["code"].astype(str).str.strip().eq("").sum()),
        "labels": {str(k): int(v) for k, v in data["label"].value_counts().items()},
        "provenance": {str(k): int(v) for k, v in data["provenance"].value_counts().items()},
        "languages": {str(k): int(v) for k, v in data["language"].value_counts().items()},
        "public_owasp": {},
        "public_api": {},
        "cwe": {str(k): int(v) for k, v in data["cwe"].astype(str).value_counts().items()},
    }
    for column, destination in (("owasp_categories", "public_owasp"), ("api_categories", "public_api")):
        values = public.loc[public.label == "vulnerable", column].str.split(";").explode()
        stats[destination] = {str(k): int(v) for k, v in values[values.ne("")].value_counts().items()}

    labels = data["label"].value_counts()
    plt.figure(figsize=(6, 4)); labels.plot.bar(color=["#b45309" if k == "vulnerable" else "#2563eb" for k in labels.index]); plt.title("Registros por etiqueta"); plt.ylabel("Registros"); plt.tight_layout(); plt.savefig(reports / "distribucion_etiquetas.png", dpi=140); plt.close()
    counts = pd.Series(stats["public_owasp"]).sort_index()
    plt.figure(figsize=(10, 4)); counts.plot.bar(color="#2563eb"); plt.title("Categorías OWASP con evidencia pública"); plt.ylabel("Casos vulnerables"); plt.xticks(rotation=35, ha="right"); plt.tight_layout(); plt.savefig(reports / "distribucion_owasp.png", dpi=140); plt.close()
    langs = data["language"].value_counts()
    plt.figure(figsize=(7, 4)); langs.plot.bar(color="#0f766e"); plt.title("Registros por lenguaje/procedencia"); plt.ylabel("Registros"); plt.tight_layout(); plt.savefig(reports / "distribucion_lenguajes.png", dpi=140); plt.close()
    (reports / "exploration.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    return stats


if __name__ == "__main__":
    summary = explore()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
