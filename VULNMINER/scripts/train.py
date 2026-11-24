"""SEMMA Modify/Model/Assess: transforma, compara, evalúa y serializa modelos."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsRestClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulnminer.catalog import API_2023, OWASP_2025
from vulnminer.features import make_vectorizer

THRESHOLD = 0.40
SEED = 42


def tags(value: str) -> list[str]:
    return [t for t in str(value).split(";") if t]


def eval_binary(y_true, y_pred) -> dict:
    labels = ["safe", "vulnerable"]
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_vulnerable": float(precision_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)),
        "recall_vulnerable": float(recall_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)),
        "f1_vulnerable": float(f1_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)),
        "confusion_matrix_labels_safe_vulnerable": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0),
    }


def multi_eval(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str]) -> dict:
    active = np.where(y_true.sum(axis=0) > 0)[0]
    if not len(active):
        return {"precision_micro": 0.0, "recall_micro": 0.0, "f1_micro": 0.0, "f1_macro_active": 0.0, "exact_match": 0.0, "per_category": {}}
    yy, pp = y_true[:, active], y_pred[:, active]
    per_category = {}
    for j, i in enumerate(active):
        per_category[classes[i]] = {
            "precision": float(precision_score(yy[:, j], pp[:, j], zero_division=0)),
            "recall": float(recall_score(yy[:, j], pp[:, j], zero_division=0)),
            "f1-score": float(f1_score(yy[:, j], pp[:, j], zero_division=0)),
            "support": int(yy[:, j].sum()),
        }
    return {
        "precision_micro": float(precision_score(yy, pp, average="micro", zero_division=0)),
        "recall_micro": float(recall_score(yy, pp, average="micro", zero_division=0)),
        "f1_micro": float(f1_score(yy, pp, average="micro", zero_division=0)),
        "f1_macro_active": float(f1_score(yy, pp, average="macro", zero_division=0)),
        "exact_match": float((yy == pp).all(axis=1).mean()),
        "per_category": per_category,
    }


def train(dataset: Path = ROOT / "data/vulnerabilities.csv", output: Path = ROOT / "models", reports: Path = ROOT / "reports") -> dict:
    df = pd.read_csv(dataset).fillna("")
    public = df[df["provenance"] == "OWASP Benchmark Java 1.2"].copy().reset_index(drop=True)
    teacher = df[df["provenance"] == "Dataset profesor (muestra deduplicada)"]
    synthetic = df[df["synthetic"].astype(str).str.lower().isin(["true", "1"])].copy()
    train_idx, remainder_idx = train_test_split(np.arange(len(public)), test_size=0.30, random_state=SEED, stratify=public["label"])
    validation_idx, test_idx = train_test_split(remainder_idx, test_size=0.50, random_state=SEED, stratify=public.iloc[remainder_idx]["label"])
    public_train, public_validation, public_test = public.iloc[train_idx], public.iloc[validation_idx], public.iloc[test_idx]
    extra = pd.concat([teacher, synthetic], ignore_index=True)
    train_frame = pd.concat([public_train, extra], ignore_index=True)

    binary_models = {}
    binary_results = {}
    for name, classifier in (
        ("logistic_regression", LogisticRegression(max_iter=1500, class_weight="balanced", C=1.0, random_state=SEED)),
        ("complement_nb", ComplementNB(alpha=0.35)),
    ):
        model = Pipeline([("features", make_vectorizer()), ("classifier", classifier)])
        model.fit(train_frame["code"].astype(str), train_frame["label"].astype(str))
        pred = model.predict(public_validation["code"].astype(str))
        binary_models[name] = model
        binary_results[name] = eval_binary(public_validation["label"].astype(str), pred)

    chosen_name = max(binary_results, key=lambda name: (binary_results[name]["f1_macro"], binary_results[name]["recall_vulnerable"]))
    final_frame = pd.concat([public_train, public_validation, extra], ignore_index=True)
    final_classifier = LogisticRegression(max_iter=1500, class_weight="balanced", C=1.0, random_state=SEED) if chosen_name == "logistic_regression" else ComplementNB(alpha=0.35)
    binary_model = Pipeline([("features", make_vectorizer()), ("classifier", final_classifier)])
    binary_model.fit(final_frame["code"].astype(str), final_frame["label"].astype(str))
    binary_pred = binary_model.predict(public_test["code"].astype(str))
    if hasattr(binary_model.named_steps["classifier"], "predict_proba"):
        vulnerable_col = list(binary_model.named_steps["classifier"].classes_).index("vulnerable")
        vulnerable_prob = binary_model.predict_proba(public_test["code"].astype(str))[:, vulnerable_col]
    else:
        vulnerable_prob = (binary_pred == "vulnerable").astype(float)

    # Multietiqueta OWASP y API: dos clasificadores supervisados separados.
    vuln_train = final_frame[final_frame["label"] == "vulnerable"].copy()
    vuln_test = public_test[public_test["label"] == "vulnerable"].copy()
    owasp_classes = sorted(OWASP_2025)
    api_classes = sorted(API_2023)
    owasp_mlb = MultiLabelBinarizer(classes=owasp_classes).fit([[]])
    api_mlb = MultiLabelBinarizer(classes=api_classes).fit([[]])
    y_owasp_train = owasp_mlb.transform([tags(x) for x in vuln_train["owasp_categories"]])
    y_api_train = api_mlb.transform([tags(x) for x in vuln_train["api_categories"]])

    def fit_multi(y):
        model = Pipeline([("features", make_vectorizer()), ("classifier", OneVsRestClassifier(LogisticRegression(max_iter=1500, class_weight="balanced", C=1.0), n_jobs=-1))])
        return model.fit(vuln_train["code"].astype(str), y)

    owasp_model = fit_multi(y_owasp_train)
    api_model = fit_multi(y_api_train)
    owasp_test_y = owasp_mlb.transform([tags(x) for x in vuln_test["owasp_categories"]])
    api_test_y = api_mlb.transform([tags(x) for x in vuln_test["api_categories"]])
    owasp_scores = owasp_model.predict_proba(vuln_test["code"].astype(str))
    api_scores = api_model.predict_proba(vuln_test["code"].astype(str))
    owasp_pred = (owasp_scores >= THRESHOLD).astype(int)
    api_pred = (api_scores >= THRESHOLD).astype(int)

    metrics = {
        "dataset": str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT) else str(dataset),
        "public_benchmark_records": int(len(public)),
        "synthetic_training_records": int(len(synthetic)),
        "teacher_training_records": int(len(teacher)),
        "train_public_records": int(len(public_train)),
        "validation_public_records": int(len(public_validation)),
        "test_public_records": int(len(public_test)),
        "split": "70/15/15 estratificado por etiqueta; validation selecciona el algoritmo; test solo OWASP Benchmark Java 1.2; el proyecto de origen es el mismo y la extrapolación externa no queda demostrada",
        "seed": SEED,
        "comparison": binary_results,
        "selected_binary_model": chosen_name,
        "binary_test": eval_binary(public_test["label"].astype(str), binary_pred),
        "owasp_multilabel_test": multi_eval(owasp_test_y, owasp_pred, owasp_classes),
        "api_multilabel_test": multi_eval(api_test_y, api_pred, api_classes),
        "category_threshold": THRESHOLD,
        "owasp_public_test_support": {owasp_classes[i]: int(owasp_test_y[:, i].sum()) for i in range(len(owasp_classes)) if owasp_test_y[:, i].sum() > 0},
        "api_public_test_support": {api_classes[i]: int(api_test_y[:, i].sum()) for i in range(len(api_classes)) if api_test_y[:, i].sum() > 0},
        "limitation": "Las categorías OWASP sin soporte público proceden solo de casos controlados sintéticos y no tienen evaluación independiente. Las etiquetas CWE-OWASP son mapeos curados orientativos, no equivalencias normativas.",
        "python": sys.version.split()[0],
        "scikit_learn": sklearn.__version__,
    }

    output.mkdir(parents=True, exist_ok=True); reports.mkdir(parents=True, exist_ok=True)
    bundle = {
        "binary_model": binary_model,
        "binary_classes": list(binary_model.named_steps["classifier"].classes_),
        "owasp_model": owasp_model,
        "owasp_classes": owasp_classes,
        "api_model": api_model,
        "api_classes": api_classes,
        "category_threshold": THRESHOLD,
        "selected_binary_model": chosen_name,
        "training_provenance": "OWASP Benchmark Java 1.2 + deduplicated teacher examples + explicitly labeled synthetic controls",
        "sklearn_version": sklearn.__version__,
    }
    joblib.dump(bundle, output / "vulnminer.joblib", compress=3)
    (reports / "assessment.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    errors = public_test[["source_id", "code", "label", "cwe"]].copy()
    errors["prediction"] = binary_pred
    errors["probability_vulnerable"] = vulnerable_prob
    errors["error_type"] = np.where((errors.label == "safe") & (errors.prediction == "vulnerable"), "false_positive", np.where((errors.label == "vulnerable") & (errors.prediction == "safe"), "false_negative", ""))
    errors[errors.error_type.ne("")].to_csv(reports / "classification_errors.csv", index=False, encoding="utf-8")
    per = metrics["owasp_multilabel_test"]["per_category"]
    if per:
        pd.DataFrame({"category": list(per), "f1": [v.get("f1-score", 0) for v in per.values()], "precision": [v.get("precision", 0) for v in per.values()], "recall": [v.get("recall", 0) for v in per.values()]}).to_csv(reports / "owasp_metrics.csv", index=False, encoding="utf-8")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return metrics


if __name__ == "__main__":
    train()
