"""SEMMA Modify/Model/Assess: transforma, ajusta hiperparámetros, compara, evalúa y serializa modelos."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
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
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulnminer.catalog import (
    API_2023,
    MIN_EVALUATED_TEST_SUPPORT,
    MIN_EVALUATED_TRAIN_SUPPORT,
    OWASP_2025,
)
from vulnminer.features import make_vectorizer

DEFAULT_THRESHOLD = 0.40
THRESHOLD_GRID = (0.30, 0.35, 0.40, 0.45, 0.50, 0.55)
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


def build_binary_estimator(algorithm: str, params: dict):
    if algorithm == "logistic_regression":
        return LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            C=params["C"],
            random_state=SEED,
        )
    if algorithm == "linear_svm":
        return CalibratedClassifierCV(
            estimator=LinearSVC(
                C=params["C"],
                class_weight="balanced",
                max_iter=3000,
                random_state=SEED,
            ),
            method="sigmoid",
            cv=3,
        )
    if algorithm == "random_forest":
        return RandomForestClassifier(
            n_estimators=params["n_estimators"],
            max_depth=params["max_depth"],
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=SEED,
            n_jobs=1,
        )
    if algorithm == "complement_nb":
        return ComplementNB(alpha=params["alpha"])
    raise ValueError(f"Algoritmo binario desconocido: {algorithm}")


def build_multilabel_estimator(algorithm: str, params: dict):
    if algorithm == "ovr_logistic_regression":
        base = LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            C=params["C"],
            random_state=SEED,
        )
    elif algorithm == "ovr_linear_svm":
        base = CalibratedClassifierCV(
            estimator=LinearSVC(
                C=params["C"],
                class_weight="balanced",
                max_iter=3000,
                random_state=SEED,
            ),
            method="sigmoid",
            cv=3,
        )
    elif algorithm == "ovr_complement_nb":
        base = ComplementNB(alpha=params["alpha"])
    else:
        raise ValueError(f"Algoritmo multietiqueta desconocido: {algorithm}")
    return OneVsRestClassifier(base, n_jobs=1)


def tune_binary_models(X_train, y_train, X_val, y_val) -> tuple[dict, list[dict]]:
    grid = [
        ("logistic_regression", {"C": c}) for c in (0.25, 0.5, 1.0, 2.0, 4.0)
    ] + [
        ("linear_svm", {"C": c}) for c in (0.1, 0.25, 0.5, 1.0, 2.0)
    ] + [
        ("random_forest", {"n_estimators": n, "max_depth": d})
        for n, d in ((100, 25), (150, 40))
    ] + [
        ("complement_nb", {"alpha": a}) for a in (0.1, 0.25, 0.5, 1.0)
    ]

    best_per_algo: dict[str, dict] = {}
    all_trials: list[dict] = []

    for algo, params in grid:
        print(f"[tune:binary] {algo} {params}", file=sys.stderr, flush=True)
        clf = build_binary_estimator(algo, params)
        clf.fit(X_train, y_train)
        pred = clf.predict(X_val)
        scores = eval_binary(y_val, pred)
        trial = {
            "task": "binary",
            "algorithm": algo,
            "hyperparameters": params,
            "threshold": 0.50,
            "metrics": scores,
        }
        all_trials.append(trial)
        prev = best_per_algo.get(algo)
        key = (scores["f1_macro"], scores["recall_vulnerable"])
        if prev is None or key > (
            prev["metrics"]["f1_macro"],
            prev["metrics"]["recall_vulnerable"],
        ):
            best_per_algo[algo] = trial

    return best_per_algo, all_trials


def tune_multilabel_models(
    task_name: str, X_train, y_train, X_val, y_val, classes: list[str]
) -> tuple[dict, list[dict]]:
    grid = [
        ("ovr_logistic_regression", {"C": c}) for c in (0.5, 1.0, 2.0, 4.0)
    ] + [
        ("ovr_linear_svm", {"C": c}) for c in (0.25, 0.5, 1.0, 2.0)
    ] + [
        ("ovr_complement_nb", {"alpha": a}) for a in (0.1, 0.35, 1.0)
    ]

    best_per_algo: dict[str, dict] = {}
    all_trials: list[dict] = []

    for algo, params in grid:
        print(f"[tune:{task_name}] {algo} {params}", file=sys.stderr, flush=True)
        clf = build_multilabel_estimator(algo, params)
        clf.fit(X_train, y_train)
        probas = clf.predict_proba(X_val)
        best_thr = DEFAULT_THRESHOLD
        best_scores = None
        for thr in THRESHOLD_GRID:
            pred = (probas >= thr).astype(int)
            scores = multi_eval(y_val, pred, classes)
            key = (scores["f1_macro_active"], scores["f1_micro"])
            if best_scores is None or key > (
                best_scores["f1_macro_active"],
                best_scores["f1_micro"],
            ):
                best_thr = thr
                best_scores = scores
        trial = {
            "task": task_name,
            "algorithm": algo,
            "hyperparameters": params,
            "threshold": best_thr,
            "metrics": best_scores,
        }
        all_trials.append(trial)
        prev = best_per_algo.get(algo)
        key = (best_scores["f1_macro_active"], best_scores["f1_micro"])
        if prev is None or key > (
            prev["metrics"]["f1_macro_active"],
            prev["metrics"]["f1_micro"],
        ):
            best_per_algo[algo] = trial

    return best_per_algo, all_trials


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

    # 1. Ajuste y comparación de clasificadores binarios sobre el conjunto de validación.
    val_vec = make_vectorizer()
    X_tr_bin = val_vec.fit_transform(train_frame["code"].astype(str))
    X_val_bin = val_vec.transform(public_validation["code"].astype(str))
    y_tr_bin = train_frame["label"].astype(str).to_numpy()
    y_val_bin = public_validation["label"].astype(str).to_numpy()

    binary_best_by_algo, binary_trials = tune_binary_models(
        X_tr_bin, y_tr_bin, X_val_bin, y_val_bin
    )
    chosen_binary = max(
        binary_best_by_algo.values(),
        key=lambda item: (
            item["metrics"]["f1_macro"],
            item["metrics"]["recall_vulnerable"],
        ),
    )

    # 2. Determinar categorías evaluadas vs no evaluadas con soporte público real.
    final_public_train = pd.concat([public_train, public_validation], ignore_index=True)
    vuln_train_public = final_public_train[final_public_train["label"] == "vulnerable"]
    vuln_test_public = public_test[public_test["label"] == "vulnerable"].copy()

    evaluated_owasp, not_evaluated_owasp, owasp_status = _category_status(
        OWASP_2025, vuln_train_public, vuln_test_public, "owasp_categories"
    )
    evaluated_api, not_evaluated_api, api_status = _category_status(
        API_2023, vuln_train_public, vuln_test_public, "api_categories"
    )

    owasp_mlb = MultiLabelBinarizer(classes=evaluated_owasp).fit([[]])
    api_mlb = MultiLabelBinarizer(classes=evaluated_api).fit([[]])

    # 3. Ajuste y comparación de clasificadores multietiqueta (OWASP 2025 y API 2023) en validación.
    vuln_tr_sub = train_frame[train_frame["label"] == "vulnerable"].reset_index(drop=True)
    vuln_val_sub = public_validation[public_validation["label"] == "vulnerable"].reset_index(drop=True)

    multi_val_vec = make_vectorizer()
    X_tr_multi = multi_val_vec.fit_transform(vuln_tr_sub["code"].astype(str))
    X_val_multi = multi_val_vec.transform(vuln_val_sub["code"].astype(str))

    y_owasp_tr_sub = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_tr_sub["owasp_categories"]]
    )
    y_owasp_val_sub = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_val_sub["owasp_categories"]]
    )
    y_api_tr_sub = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_tr_sub["api_categories"]]
    )
    y_api_val_sub = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_val_sub["api_categories"]]
    )

    owasp_best_by_algo, owasp_trials = tune_multilabel_models(
        "owasp_2025", X_tr_multi, y_owasp_tr_sub, X_val_multi, y_owasp_val_sub, evaluated_owasp
    )
    chosen_owasp = max(
        owasp_best_by_algo.values(),
        key=lambda item: (
            item["metrics"]["f1_macro_active"],
            item["metrics"]["f1_micro"],
        ),
    )

    api_best_by_algo, api_trials = tune_multilabel_models(
        "api_2023", X_tr_multi, y_api_tr_sub, X_val_multi, y_api_val_sub, evaluated_api
    )
    chosen_api = max(
        api_best_by_algo.values(),
        key=lambda item: (
            item["metrics"]["f1_macro_active"],
            item["metrics"]["f1_micro"],
        ),
    )

    # 4. Reentrenamiento final con train + validation y evaluación en test independiente.
    final_frame = pd.concat([final_public_train, extra], ignore_index=True)
    binary_model = Pipeline(
        [
            ("features", make_vectorizer()),
            (
                "classifier",
                build_binary_estimator(
                    chosen_binary["algorithm"], chosen_binary["hyperparameters"]
                ),
            ),
        ]
    )
    binary_model.fit(final_frame["code"].astype(str), final_frame["label"].astype(str))
    binary_train_pred = binary_model.predict(final_public_train["code"].astype(str))
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

    vuln_train = final_frame[final_frame["label"] == "vulnerable"].reset_index(drop=True)
    y_owasp_train = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_train["owasp_categories"]]
    )
    y_api_train = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_train["api_categories"]]
    )

    owasp_model = Pipeline(
        [
            ("features", make_vectorizer()),
            (
                "classifier",
                build_multilabel_estimator(
                    chosen_owasp["algorithm"], chosen_owasp["hyperparameters"]
                ),
            ),
        ]
    ).fit(vuln_train["code"].astype(str), y_owasp_train)

    api_model = Pipeline(
        [
            ("features", make_vectorizer()),
            (
                "classifier",
                build_multilabel_estimator(
                    chosen_api["algorithm"], chosen_api["hyperparameters"]
                ),
            ),
        ]
    ).fit(vuln_train["code"].astype(str), y_api_train)

    owasp_test_y = owasp_mlb.transform(
        [[t for t in tags(x) if t in evaluated_owasp] for x in vuln_test_public["owasp_categories"]]
    )
    api_test_y = api_mlb.transform(
        [[t for t in tags(x) if t in evaluated_api] for x in vuln_test_public["api_categories"]]
    )
    owasp_scores = owasp_model.predict_proba(vuln_test_public["code"].astype(str))
    api_scores = api_model.predict_proba(vuln_test_public["code"].astype(str))
    owasp_thr = float(chosen_owasp["threshold"])
    api_thr = float(chosen_api["threshold"])
    owasp_pred = (owasp_scores >= owasp_thr).astype(int)
    api_pred = (api_scores >= api_thr).astype(int)

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
        "selection_criteria": {
            "binary": "Mayor F1 macro en validación con desempate por recall de la clase vulnerable.",
            "multilabel": "Mayor F1 macro en categorías activas de validación con desempate por F1 micro (ajustando hiperparámetros y umbral).",
        },
        "comparison": {
            algo: {
                "best_hyperparameters": info["hyperparameters"],
                **info["metrics"],
            }
            for algo, info in binary_best_by_algo.items()
        },
        "owasp_comparison": {
            algo: {
                "best_hyperparameters": info["hyperparameters"],
                "best_threshold": info["threshold"],
                **info["metrics"],
            }
            for algo, info in owasp_best_by_algo.items()
        },
        "api_comparison": {
            algo: {
                "best_hyperparameters": info["hyperparameters"],
                "best_threshold": info["threshold"],
                **info["metrics"],
            }
            for algo, info in api_best_by_algo.items()
        },
        "selected_binary_model": chosen_binary["algorithm"],
        "selected_binary_hyperparameters": chosen_binary["hyperparameters"],
        "selected_owasp_model": chosen_owasp["algorithm"],
        "selected_owasp_hyperparameters": chosen_owasp["hyperparameters"],
        "selected_api_model": chosen_api["algorithm"],
        "selected_api_hyperparameters": chosen_api["hyperparameters"],
        "binary_train_eval": eval_binary(
            final_public_train["label"].astype(str), binary_train_pred
        ),
        "binary_validation_best": chosen_binary["metrics"],
        "binary_test": eval_binary(public_test["label"].astype(str), binary_pred),
        "binary_test_by_language": binary_by_lang,
        "binary_test_by_provenance": binary_by_prov,
        "owasp_multilabel_test": owasp_eval,
        "api_multilabel_test": api_eval,
        "category_threshold": owasp_thr,
        "owasp_threshold": owasp_thr,
        "api_threshold": api_thr,
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
        "category_threshold": owasp_thr,
        "owasp_threshold": owasp_thr,
        "api_threshold": api_thr,
        "selected_binary_model": chosen_binary["algorithm"],
        "selected_binary_hyperparameters": chosen_binary["hyperparameters"],
        "selected_owasp_model": chosen_owasp["algorithm"],
        "selected_owasp_hyperparameters": chosen_owasp["hyperparameters"],
        "selected_api_model": chosen_api["algorithm"],
        "selected_api_hyperparameters": chosen_api["hyperparameters"],
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

    # Exportar tabla comparativa completa de hiperparámetros y algoritmos.
    comp_rows = []
    for trial in binary_trials:
        m = trial["metrics"]
        comp_rows.append(
            {
                "task": "binary",
                "algorithm": trial["algorithm"],
                "hyperparameters": json.dumps(trial["hyperparameters"], sort_keys=True),
                "threshold": trial["threshold"],
                "val_accuracy": round(m["accuracy"], 4),
                "val_precision_macro": round(m["precision_macro"], 4),
                "val_recall_macro": round(m["recall_macro"], 4),
                "val_f1_macro": round(m["f1_macro"], 4),
                "val_secondary_metric": round(m["recall_vulnerable"], 4),
                "selected": trial is chosen_binary,
            }
        )
    for trial, winner in (
        *[(t, chosen_owasp) for t in owasp_trials],
        *[(t, chosen_api) for t in api_trials],
    ):
        m = trial["metrics"]
        comp_rows.append(
            {
                "task": trial["task"],
                "algorithm": trial["algorithm"],
                "hyperparameters": json.dumps(trial["hyperparameters"], sort_keys=True),
                "threshold": trial["threshold"],
                "val_accuracy": round(m["exact_match"], 4),
                "val_precision_macro": round(m["precision_micro"], 4),
                "val_recall_macro": round(m["recall_micro"], 4),
                "val_f1_macro": round(m["f1_macro_active"], 4),
                "val_secondary_metric": round(m["f1_micro"], 4),
                "selected": trial is winner,
            }
        )
    pd.DataFrame(comp_rows).to_csv(
        reports / "model_comparison.csv", index=False, encoding="utf-8"
    )

    errors = public_test[
        ["source_id", "provenance", "language", "code", "label", "cwe"]
    ].copy()
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
