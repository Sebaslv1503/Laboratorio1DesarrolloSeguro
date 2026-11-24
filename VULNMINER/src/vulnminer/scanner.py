"""Lectura de repositorios, descubrimiento de servicios y evaluación ML."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import joblib

from .catalog import API_2023, OWASP_2025, REMEDIATION
from .features import SIGNALS

SOURCE_EXTENSIONS = {".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".yml", ".yaml", ".properties", ".toml", ".json", ".xml", ".env", ".conf", ".ini", ".config"}
CONFIG_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "requirements.txt", "package-lock.json", "pom.xml", "build.gradle"}
IGNORE_NAMES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", "dist", "build", "target", "vendor", "site-packages", "coverage"}
SERVICE_MARKERS = {"package.json", "pom.xml", "pyproject.toml", "requirements.txt", "go.mod", "dockerfile", "docker-compose.yml", "docker-compose.yaml"}

EVIDENCE = {
    "sql_sink": (89, "Concatenación de datos no confiables en una operación SQL"),
    "sql_parameterized": (None, "Uso de parámetros/consulta preparada observado"),
    "html_sink": (79, "Posible salida HTML con datos de entrada"),
    "safe_text_sink": (None, "Uso de salida de texto o sanitización observado"),
    "shell_sink": (78, "Posible ejecución de comando con datos variables"),
    "shell_safe": (None, "Ejecución de proceso con señales de parametrización observada"),
    "path_sink": (22, "Ruta/archivo construido con datos variables"),
    "path_guard": (None, "Señal de normalización o validación de ruta observada"),
    "weak_crypto": (327, "Algoritmo o modo criptográfico débil mencionado"),
    "safe_crypto": (None, "Primitiva criptográfica moderna mencionada"),
    "unsafe_deserialization": (502, "Deserialización de datos no confiables potencialmente riesgosa"),
    "debug_enabled": (16, "Configuración de depuración, CORS o exposición amplia observada"),
    "external_request": (918, "Solicitud saliente con destino variable observada"),
    "owner_check": (639, "Comprobación de propietario/autorización observada"),
    "auth_check": (287, "Control de autenticación/autorización mencionado"),
    "resource_limit": (770, "Límite de recursos o tiempo observado"),
    "mass_assignment": (915, "Asignación masiva desde propiedades de solicitud observada"),
    "exception_suppressed": (703, "Excepción ignorada o convertida en valor de retorno"),
    "dependency_source": (829, "Referencia de dependencia o artefacto observada"),
    "security_logging": (778, "Registro o auditoría de seguridad mencionados"),
}


def language(path: Path) -> str:
    return {".py": "Python", ".java": "Java", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript"}.get(path.suffix.lower(), "Configuration")


def is_candidate(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS or path.name.lower() in CONFIG_NAMES


def iter_files(root: Path, output: Path | None = None):
    root = root.resolve()
    excluded = output.resolve() if output else None
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d.lower() not in IGNORE_NAMES and not d.startswith(".")]
        if excluded and (current_path == excluded or excluded in current_path.parents):
            dirs[:] = []
            continue
        for filename in files:
            path = current_path / filename
            if is_candidate(path) and path.stat().st_size <= 1_000_000:
                yield path


def service_for(path: Path, root: Path) -> str:
    current = path.parent
    while current != root and root in current.parents:
        try:
            if any((current / marker).is_file() for marker in SERVICE_MARKERS):
                return current.relative_to(root).as_posix()
        except OSError:
            pass
        current = current.parent
    return root.name or "."


def evidence_for(code: str) -> tuple[int, str, int | None] | None:
    return next(iter(evidences_for(code)), None)


def evidences_for(code: str) -> list[tuple[int, str, int | None]]:
    found = []
    for lineno, line in enumerate(code.splitlines(), 1):
        for name, pattern in SIGNALS.items():
            if re.search(pattern, line):
                cwe, description = EVIDENCE.get(name, (None, name))
                if name in {"sql_parameterized", "safe_text_sink", "shell_safe", "path_guard", "safe_crypto", "owner_check", "auth_check", "resource_limit", "security_logging"}:
                    continue
                found.append((lineno, description, cwe))
                break
    return found


def prediction_vector(model, text: str) -> tuple[list[str], list[float]]:
    classes = model.named_steps["classifier"].classes_
    names = ["safe" if c == "safe" else "vulnerable" for c in classes]
    proba = model.predict_proba([text])[0]
    return names, [float(x) for x in proba]


def _multilabel(model, code: str, classes: list[str], threshold: float) -> list[dict]:
    probabilities = model.predict_proba([code])[0]
    return [{"code": category, "name": (API_2023 if category.startswith("API") else OWASP_2025).get(category, category), "confidence": float(prob)}
            for category, prob in zip(classes, probabilities) if float(prob) >= threshold]


def classify_chunk(bundle: dict, chunk: str) -> tuple[float, list[dict], list[dict]]:
    names, probabilities = prediction_vector(bundle["binary_model"], chunk)
    risk_probability = probabilities[names.index("vulnerable")]
    prediction = bundle["binary_model"].predict([chunk])[0]
    if prediction != "vulnerable" or risk_probability < 0.55:
        return risk_probability, [], []
    threshold = float(bundle.get("category_threshold", 0.4))
    return risk_probability, _multilabel(bundle["owasp_model"], chunk, bundle["owasp_classes"], threshold), _multilabel(bundle["api_model"], chunk, bundle["api_classes"], threshold)


def scan(root: Path, model_path: Path, standards: set[str] | None = None, output: Path | None = None) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"No existe el directorio del proyecto: {root}")
    if not model_path.is_file():
        raise FileNotFoundError(f"Modelo entrenado no encontrado: {model_path}; ejecute scripts/train.py una vez.")
    bundle = joblib.load(model_path)
    standards = standards or {"owasp2025", "api2023"}
    findings = []
    files = list(iter_files(root, output))
    services = set()
    category_threshold = float(bundle.get("category_threshold", 0.4))
    for file in files:
        try:
            code = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        service = service_for(file, root)
        services.add(service)
        lines = code.splitlines()
        contexts = []
        for location, clue, cwe in evidences_for(code)[:100]:
            start, end = max(1, location - 3), min(len(lines), location + 3)
            contexts.append((location, clue, cwe, "\n".join(lines[start - 1:end])))
        # Respaldo a nivel de archivo solo para predicciones muy seguras sin señal local;
        # manifiestos sin indicios concretos no se reportan por su vocabulario habitual.
        if not contexts:
            probability, _, _ = classify_chunk(bundle, code)
            if probability >= 0.85 and file.suffix.lower() in {".py", ".java", ".js", ".ts", ".jsx", ".tsx"}:
                contexts.append((1, "El clasificador detectó similitud con ejemplos etiquetados; no se aisló una señal local.", None, code))
        rel = file.relative_to(root).as_posix()
        for location, clue, cwe, chunk in contexts:
            vuln_probability, owasp, api = classify_chunk(bundle, chunk)
            if vuln_probability < 0.55:
                continue
            if "owasp2025" not in standards:
                owasp = []
            if "api2023" not in standards:
                api = []
            assigned = bool(owasp or api)
            category_names = [x["name"] for x in owasp + api]
            key = f"{rel}:{location}:{','.join(x['code'] for x in owasp + api)}"
            finding_id = hashlib.sha1(key.encode()).hexdigest()[:12].upper()
            severity = "high" if any(x["code"] in {"A01:2025", "A04:2025", "A05:2025", "API1:2023", "API2:2023", "API5:2023", "API7:2023"} for x in owasp + api) else "medium"
            recommendations = list(dict.fromkeys(REMEDIATION[x["code"]] for x in owasp + api))
            findings.append({
                "id": finding_id,
                "microservice": service,
                "file": rel,
                "language": language(file),
                "line": location,
                "problem": category_names[0] if category_names else "Patrón potencial para revisión manual",
                "evidence": {"description": clue, "line_excerpt": lines[location - 1].strip()[:500] if lines else "", "cwe": f"CWE-{cwe}" if cwe else None},
                "owasp_top10_2025": owasp,
                "owasp_api_2023": api,
                "confidence": round(vuln_probability, 4),
                "category_confidence": round(max((x["confidence"] for x in owasp + api), default=0.0), 4),
                "severity_estimate": severity,
                "severity_basis": "Estimación didáctica basada en categorías predichas; no es CVSS ni la probabilidad del modelo.",
                "recommendations": recommendations or ["Revisar manualmente el contexto del código y validar la ruta de datos."],
                "status": "requires_manual_review" if assigned else "unclassified_review_required",
                "classification_basis": "Modelo supervisado aplicado a contexto alrededor de una señal estática; la señal solo aporta evidencia y ubicación.",
            })
    return {
        "tool": "VULNMINER",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(root),
        "standards": sorted(standards),
        "summary": {"microservices": len(services), "files_analyzed": len(files), "potential_findings": len(findings)},
        "support_notice": "OWASP 2025: evaluación pública disponible para A01, A02, A04, A05 y A08. OWASP API: evidencia pública solo API8. Otras etiquetas tuvieron entrenamiento sintético controlado y requieren validación manual; no implican cobertura validada.",
        "findings": findings,
    }


def write_reports(report: dict, output: Path, formats: set[str]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in formats:
        target = output / "analysis.json"
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(target)
    if "html" in formats:
        rows = []
        for item in report["findings"]:
            owasp = ", ".join(html.escape(x["code"]) for x in item["owasp_top10_2025"]) or "—"
            api = ", ".join(html.escape(x["code"]) for x in item["owasp_api_2023"]) or "—"
            rows.append(f"<tr><td>{html.escape(item['id'])}</td><td>{html.escape(item['microservice'])}</td><td>{html.escape(item['file'])}:{item['line']}</td><td>{owasp}</td><td>{api}</td><td>{item['confidence']:.2f}</td><td>{html.escape(item['evidence']['description'])}<pre>{html.escape(item['evidence']['line_excerpt'])}</pre></td><td>{html.escape('; '.join(item['recommendations']))}</td></tr>")
        doc = """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>VULNMINER - Reporte</title><style>body{font:15px system-ui,sans-serif;margin:2rem;color:#172033}h1{color:#12315a}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ccd4df;padding:8px;text-align:left;vertical-align:top}th{background:#edf2f8}pre{white-space:pre-wrap;background:#f5f7fa;padding:6px}.notice{background:#fff7da;padding:12px;border-left:4px solid #d79b00}</style></head><body><h1>VULNMINER - análisis de seguridad</h1><p>Proyecto: """ + html.escape(report["project_root"]) + "</p><p>Microservicios: " + str(report["summary"]["microservices"]) + " | Archivos: " + str(report["summary"]["files_analyzed"]) + " | Hallazgos potenciales: " + str(report["summary"]["potential_findings"]) + "</p><p class=notice>" + html.escape(report["support_notice"]) + "</p><table><thead><tr><th>ID</th><th>Servicio</th><th>Archivo:línea</th><th>OWASP 2025</th><th>OWASP API 2023</th><th>Confianza</th><th>Evidencia</th><th>Recomendación</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></body></html>"
        target = output / "analysis.html"
        target.write_text(doc, encoding="utf-8")
        written.append(target)
    return written
