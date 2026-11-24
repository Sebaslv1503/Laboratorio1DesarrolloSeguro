"""Interfaz de línea de comandos VULNMINER."""
from __future__ import annotations

import argparse
from pathlib import Path

from .scanner import scan, write_reports

DEFAULT_MODEL = Path(__file__).resolve().parents[2] / "models" / "vulnminer.joblib"


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="vulnminer", description="Clasificador experimental de riesgos de código para microservicios")
    commands = cli.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("scan", help="analiza un proyecto o repositorio")
    cmd.add_argument("path", type=Path, help="directorio raíz del proyecto")
    cmd.add_argument("--standards", default="owasp2025,api2023", help="lista separada por coma: owasp2025,api2023")
    cmd.add_argument("--format", default="json,html", help="formatos de salida: json,html")
    cmd.add_argument("--output", type=Path, default=Path("./reportes"), help="directorio de reportes")
    cmd.add_argument("--model", type=Path, default=DEFAULT_MODEL, help="ruta alternativa del modelo serializado")
    return cli


def main() -> int:
    args = parser().parse_args()
    standards = {x.strip().lower() for x in args.standards.split(",") if x.strip()}
    formats = {x.strip().lower() for x in args.format.split(",") if x.strip()}
    unknown = standards - {"owasp2025", "api2023"}
    bad_formats = formats - {"json", "html"}
    if unknown or not standards:
        raise SystemExit(f"Estándares no válidos: {', '.join(sorted(unknown)) or '(vacío)'}")
    if bad_formats or not formats:
        raise SystemExit(f"Formatos no válidos: {', '.join(sorted(bad_formats)) or '(vacío)'}")
    report = scan(args.path, args.model, standards, args.output)
    paths = write_reports(report, args.output, formats)
    print("=" * 48)
    print("VULNMINER - SECURITY SCAN")
    print("=" * 48)
    print(f"Proyecto: {report['project_root']}")
    print(f"Microservicios: {report['summary']['microservices']}")
    print(f"Archivos analizados: {report['summary']['files_analyzed']}")
    print(f"Hallazgos potenciales: {report['summary']['potential_findings']}")
    for finding in report["findings"]:
        print(f"- {finding['microservice']} | {finding['file']}:{finding['line']} | confianza {finding['confidence']:.2f} | {finding['problem']}")
    print("Reportes:")
    for path in paths:
        print(f"  {path}")
    return 0
