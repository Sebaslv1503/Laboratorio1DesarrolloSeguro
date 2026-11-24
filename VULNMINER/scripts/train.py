"""SEMMA Modify/Model/Assess: transforma, compara, evalúa y serializa modelos."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.multiclass import OneVsRestClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulnminer.catalog import (
    API_2023,
    MIN_EVALUATED_TEST_SUPPORT,
    MIN_EVALUATED_TRAIN_SUPPORT,
    OWASP_2025,
)
from vulnminer.features import make_vectorizer

THRESHOLD = 0.40
SEED = 42


def tags(value: str) -> list[str]:
    return [t for t in str(value).split(";") if t]


def group_stratified_split(
    public: pd.DataFrame, seed: int = SEED
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Divide filas públicas en 70/15/15 sin compartir split_group entre particiones."""
    rng = np.random.default_rng(seed)
    group_meta: list[tuple[str, str, int]] = []
    for grp, frame in public.groupby("split_group", sort=True):
        prov = str(frame["provenance"].iloc[0])
        lang = str(frame["language"].iloc[0])
        vuln_rows = frame[frame["label"] == "vulnerable"]
        if len(vuln_rows):
            api_tag = next((tags(x)[0] for x in vuln_rows["api_categories"] if tags(x)), "")
            ow_tag = next((tags(x)[0] for x in vuln_rows["owasp_categories"] if tags(x)), "")
            cat_key = api_tag or ow_tag or "vuln"
        else:
            cat_key = "safe"
        stratum = f"{prov}|{lang}|{cat_key}"
        group_meta.append((str(grp), stratum, len(frame)))

    by_stratum: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for grp, stratum, count in group_meta:
        by_stratum[stratum].append((grp, count))

    split_groups: dict[str, set[str]] = {"train": set(), "val": set(), "test": set()}
    ratios = {"train": 0.70, "val": 0.15, "test": 0.15}

    for stratum in sorted(by_stratum):
        items = list(by_stratum[stratum])
        order = rng.permutation(len(items))
        items = [items[i] for i in order]
        items.sort(key=lambda x: -x[1])
        total_rows = sum(c for _, c in items)
        counts = {"train": 0, "val": 0, "test": 0}
        for grp, size in items:
            best_split = max(
                ("train", "val", "test"),
                key=lambda s: (ratios[s] * total_rows - counts[s], ratios[s]),
            )
            split_groups[best_split].add(grp)
            counts[best_split] += size

    assert not (split_groups["train"] & split_groups["val"])
    assert not (split_groups["train"] & split_groups["test"])
    assert not (split_groups["val"] & split_groups["test"])

    train_df = public[public["split_group"].isin(split_groups["train"])].reset_index(drop=True)
    val_df = public[public["split_group"].isin(split_groups["val"])].reset_index(drop=True)
    test_df = public[public["split_group"].isin(split_groups["test"])].reset_index(drop=True)
    return train_df, val_df, test_df


def eval_binary(y_true, y_pred) -> dict:
    labels = ["safe", "vulnerable"]
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(
            precision_score(y_true, y_pred, average="macro", zero_division=0)
        ),
        "recall_macro": float(
            recall_score(y_true, y_pred, average="macro", zero_division=0)
        ),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_vulnerable": float(
            precision_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)
        ),
        "recall_vulnerable": float(
            recall_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)
        ),
        "f1_vulnerable": float(
            f1_score(y_true, y_pred, pos_label="vulnerable", zero_division=0)
        ),
        "confusion_matrix_labels_safe_vulnerable": confusion_matrix(
            y_true, y_pred, labels=labels
        ).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, output_dict=True, zero_division=0
        ),
    }


def multi_eval(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str]) -> dict:
    active = np.where(y_true.sum(axis=0) > 0)[0]
    if not len(active):
        return {
            "precision_micro": 0.0,
            "recall_micro": 0.0,
            "f1_micro": 0.0,
            "f1_macro_active": 0.0,
            "exact_match": 0.0,
            "per_category": {},
        }
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
        "precision_micro": float(
            precision_score(yy, pp, average="micro", zero_division=0)
        ),
        "recall_micro": float(recall_score(yy, pp, average="micro", zero_division=0)),
        "f1_micro": float(f1_score(yy, pp, average="micro", zero_division=0)),
        "f1_macro_active": float(f1_score(yy, pp, average="macro", zero_division=0)),
        "exact_match": float((yy == pp).all(axis=1).mean()),
        "per_category": per_category,
    }


def _category_status(
    catalog: dict[str, str],
    train_vuln_public: pd.DataFrame,
    test_vuln_public: pd.DataFrame,
    column: str,
) -> tuple[list[str], list[str], dict[str, dict]]:
    train_counts: dict[str, int] = defaultdict(int)
    for val in train_vuln_public[column]:
        for tag in tags(val):
            train_counts[tag] += 1
    test_counts: dict[str, int] = defaultdict(int)
    for val in test_vuln_public[column]:
        for tag in tags(val):
            test_counts[tag] += 1

    evaluated: list[str] = []
    not_evaluated: list[str] = []
    status_map: dict[str, dict] = {}
    for code, name in catalog.items():
        tr_n = train_counts[code]
        te_n = test_counts[code]
        if tr_n >= MIN_EVALUATED_TRAIN_SUPPORT and te_n >= MIN_EVALUATED_TEST_SUPPORT:
            evaluated.append(code)
            status_map[code] = {
                "name": name,
                "status": "evaluada",
                "train_public_support": tr_n,
                "test_public_support": te_n,
            }
        else:
            not_evaluated.append(code)
            status_map[code] = {
                "name": name,
                "status": "no evaluada",
                "train_public_support": tr_n,
                "test_public_support": te_n,
                "reason": (
                    f"Soporte público insuficiente (train={tr_n} < {MIN_EVALUATED_TRAIN_SUPPORT} "
                    f"o test={te_n} < {MIN_EVALUATED_TEST_SUPPORT}); requiere datos adicionales o revisión contextual/dinámica."
                ),
            }
    return sorted(evaluated), sorted(not_evaluated), status_map


def train(
    dataset: Path = ROOT / "data/vulnerabilities.csv",
    output: Path = ROOT / "models",
    reports: Path = ROOT / "reports",
) -> dict:
    df = pd.read_csv(dataset).fillna("")
    is_synth = df["synthetic"].astype(str).str.lower().isin(["true", "1"])
    is_teacher = df["provenance"] == "Dataset profesor (muestra deduplicada)"
    public = df[~is_synth & ~is_teacher].copy().reset_index(drop=True)
    teacher = df[is_teacher].copy()
    synthetic = df[is_synth].copy()

    public_train, public_validation, public_test = group_stratified_split(public, SEED)
    extra = pd.concat([teacher, synthetic], ignore_index=True)
    train_frame = pd.concat([public_train, extra], ignore_index=True)

    binary_models = {}
    binary_results = {}
    for name, classifier in (
        (
            "logistic_regression",
            LogisticRegression(
                max_iter=1500, class_weight="balanced", C=1.0, random_state=SEED
            ),
        ),
        ("complement_nb", ComplementNB(alpha=0.35)),
    ):
        model = Pipeline([("features", make_vectorizer()), ("classifier", classifier)])
        model.fit(train_frame["code"].astype(str), train_frame["label"].astype(str))
        pred = model.predict(public_validation["code"].astype(str))
        binary_models[name] = model
        binary_results[name] = eval_binary(public_validation["label"].astype(str), pred)

    chosen_name = max(
        binary_results,
        key=lambda name: (
            binary_results[name]["f1_macro"],
            binary_results[name]["recall_vulnerable"],
        ),
    )
    final_public_train = pd.concat([public_train, public_validation], ignore_index=True)
    final_frame = pd.concat([final_public_train, extra], ignore_index=True)
    final_classifier = (
        LogisticRegression(
            max_iter=1500, class_weight="balanced", C=1.0, random_state=SEED
        )
        if chosen_name == "logistic_regression"
        else ComplementNB(alpha=0.35)
    )
    binary_model = Pipeline(
        [("features", make_vectorizer()), ("classifier", final_classifier)]
    )
    binary_model.fit(final_frame["code"].astype(str), final_frame["label"].astype(str))
    binary_pred = binary_model.predict(public_test["code"].astype(str))
    if hasattr(binary_model.named_steps["classifier"], "predict_proba"):
        vulnerable_col = list(binary_model.named_steps["classifier"].classes_).index(
            "vulnerable"
        )
        vulnerable_prob = binary_model.predict_proba(
            public_test["code"].astype(str)
        )[:, vulnerable_col]
    else:
        vulnerable_prob = (binary_pred == "vulnerable").astype(float)

    binary_by_lang = {}
    for lang, grp in public_test.groupby("language"):
        idx = grp.index.to_numpy()
        binary_by_lang[str(lang)] = {
            "support": int(len(grp)),
            **eval_binary(grp["label"].astype(str), binary_pred[idx]),
        }

    binary_by_prov = {}
    for prov, grp in public_test.groupby("provenance"):
        idx = grp.index.to_numpy()
        binary_by_prov[str(prov)] = {
            "support": int(len(grp)),
            **eval_binary(grp["label"].astype(str), binary_pred[idx]),
        }

    # Determinar categorías evaluadas vs no evaluadas con soporte público real.
    vuln_train_public = final_public_train[final_public_train["label"] == "vulnerable"]
    vuln_test_public = public_test[public_test["label"] == "vulnerable"].copy()

    evaluated_owasp, not_evaluated_owasp, owasp_status = _category_status(
        OWASP_2025, vuln_train_public, vuln_test_public, "owasp_categories"
    )
    evaluated_api, not_evaluated_api, api_status = _category_status(
        API_2023, vuln_train_public, vuln_test_public, "api_categories"
    )

    vuln_train = final_frame[final_frame["label"] == "vulnerable"].copy()
    owasp_mlb = MultiLabelBinarizer(classes=evaluated_owasp).fit([[]])
    api_mlb = MultiLabelBinarizer(classes=evaluated_api).fit([[]])

    y_owasp_train = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_train["owasp_categories"]]
    )
    y_api_train = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_train["api_categories"]]
    )

    def fit_multi(y):
        model = Pipeline(
            [
                ("features", make_vectorizer()),
                (
                    "classifier",
                    OneVsRestClassifier(
                        LogisticRegression(
                            max_iter=1500, class_weight="balanced", C=1.0
                        ),
                        n_jobs=1,
                    ),
                ),
            ]
        )
        return model.fit(vuln_train["code"].astype(str), y)

    owasp_model = fit_multi(y_owasp_train)
    api_model = fit_multi(y_api_train)

    owasp_test_y = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_test_public["owasp_categories"]]
    )
    api_test_y = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_test_public["api_categories"]]
    )
    owasp_scores = owasp_model.predict_proba(vuln_test_public["code"].astype(str))
    api_scores = api_model.predict_proba(vuln_test_public["code"].astype(str))
    owasp_pred = (owasp_scores >= THRESHOLD).astype(int)
    api_pred = (api_scores >= THRESHOLD).astype(int)

    owasp_eval = multi_eval(owasp_test_y, owasp_pred, evaluated_owasp)
    api_eval = multi_eval(api_test_y, api_pred, evaluated_api)

    metrics = {
        "dataset": str(dataset.relative_to(ROOT))
        if dataset.is_relative_to(ROOT)
        else str(dataset),
        "public_records": int(len(public)),
        "public_by_provenance": {
            str(k): int(v) for k, v in public["provenance"].value_counts().items()
        },
        "public_by_language": {
            str(k): int(v) for k, v in public["language"].value_counts().items()
        },
        "synthetic_training_records": int(len(synthetic)),
        "teacher_training_records": int(len(teacher)),
        "train_public_records": int(len(public_train)),
        "validation_public_records": int(len(public_validation)),
        "test_public_records": int(len(public_test)),
        "test_languages": {
            str(k): int(v) for k, v in public_test["language"].value_counts().items()
        },
        "split": (
            "70/15/15 estratificado por fuente/lenguaje/categoría y agrupado por split_group "
            "(cero fuga de archivos de regla o casos entre train, validation y test); "
            "muestras sintéticas y del docente solo en entrenamiento."
        ),
        "seed": SEED,
        "comparison": binary_results,
        "selected_binary_model": chosen_name,
        "binary_test": eval_binary(public_test["label"].astype(str), binary_pred),
        "binary_test_by_language": binary_by_lang,
        "binary_test_by_provenance": binary_by_prov,
        "owasp_multilabel_test": owasp_eval,
        "api_multilabel_test": api_eval,
        "category_threshold": THRESHOLD,
        "evaluated_owasp": evaluated_owasp,
        "not_evaluated_owasp": not_evaluated_owasp,
        "evaluated_api": evaluated_api,
        "not_evaluated_api": not_evaluated_api,
        "owasp_category_status": owasp_status,
        "api_category_status": api_status,
        "owasp_public_test_support": {
            evaluated_owasp[i]: int(owasp_test_y[:, i].sum())
            for i in range(len(evaluated_owasp))
            if owasp_test_y[:, i].sum() > 0
        },
        "api_public_test_support": {
            evaluated_api[i]: int(api_test_y[:, i].sum())
            for i in range(len(evaluated_api))
            if api_test_y[:, i].sum() > 0
        },
        "limitation": (
            "Las categorías declaradas como 'no evaluada' no cuentan con soporte público suficiente "
            "o requieren análisis dinámico/contextual y no se asignan automáticamente. "
            "Las correspondencias CWE-OWASP son mapeos orientativos documentados."
        ),
        "python": sys.version.split()[0],
        "scikit_learn": sklearn.__version__,
    }

    output.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    bundle = {
        "binary_model": binary_model,
        "binary_classes": list(binary_model.named_steps["classifier"].classes_),
        "owasp_model": owasp_model,
        "owasp_classes": evaluated_owasp,
        "api_model": api_model,
        "api_classes": evaluated_api,
        "evaluated_owasp": evaluated_owasp,
        "not_evaluated_owasp": not_evaluated_owasp,
        "evaluated_api": evaluated_api,
        "not_evaluated_api": not_evaluated_api,
        "category_threshold": THRESHOLD,
        "selected_binary_model": chosen_name,
        "training_provenance": (
            "OWASP Benchmark Java 1.2 + OWASP Benchmark Python 0.1 + "
            "Semgrep Community Rules + teacher sample + controlled config pairs"
        ),
        "sklearn_version": sklearn.__version__,
    }
    joblib.dump(bundle, output / "vulnminer.joblib", compress=3)
    (reports / "assessment.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    errors = public_test[["source_id", "provenance", "language", "code", "label", "cwe"]].copy()
    errors["prediction"] = binary_pred
    errors["probability_vulnerable"] = vulnerable_prob
    errors["error_type"] = np.where(
        (errors.label == "safe") & (errors.prediction == "vulnerable"),
        "false_positive",
        np.where(
            (errors.label == "vulnerable") & (errors.prediction == "safe"),
            "false_negative",
            "",
        ),
    )
    errors[errors.error_type.ne("")].to_csv(
        reports / "classification_errors.csv", index=False, encoding="utf-8"
    )

    # Exportar las 20 categorías (evaluadas y no evaluadas) en owasp_metrics.csv
    metric_rows = []
    for standard, catalog, status_map, per_cat in (
        ("OWASP Top 10:2025", OWASP_2025, owasp_status, owasp_eval["per_category"]),
        ("OWASP API Security Top 10:2023", API_2023, api_status, api_eval["per_category"]),
    ):
        for code, name in catalog.items():
            info = status_map[code]
            scores = per_cat.get(code, {})
            metric_rows.append(
                {
                    "standard": standard,
                    "category": code,
                    "name": name,
                    "status": info["status"],
                    "train_public_support": info["train_public_support"],
                    "test_public_support": info["test_public_support"],
                    "precision": round(scores["precision"], 4) if scores else "",
                    "recall": round(scores["recall"], 4) if scores else "",
                    "f1": round(scores["f1-score"], 4) if scores else "",
                }
            )
    pd.DataFrame(metric_rows).to_csv(
        reports / "owasp_metrics.csv", index=False, encoding="utf-8"
    )
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return metrics


if __name__ == "__main__":
    train()
