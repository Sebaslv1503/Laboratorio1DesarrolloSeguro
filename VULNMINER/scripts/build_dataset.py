"""SEMMA Sample: normaliza fuentes y construye el dataset trazable."""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "src"))
from vulnminer.catalog import API_CWE, OWASP_CWE

SCHEMA = ["record_id", "code", "language", "label", "cwe", "owasp_categories", "api_categories", "provenance", "source_id", "split_group", "synthetic"]

API_CASES = [
    (639, ["@GetMapping('/orders/{orderId}') def get_order(orderId, user): return db.get(orderId)", "function readInvoice(req) { return store.find(req.params.id); }", "GET /v2/customers/{customerId}/records -> repository.findById(customerId)"]),
    (287, ["def login(request): return create_token(request.json['password'], verify=False)", "jwt.decode(token, options={'verify_signature': False})", "app.post('/login', (req,res) => res.json({token: sign(req.body, 'secret')}))"]),
    (915, ["user.update(request.json)  # mass assignment of role", "Object.assign(account, req.body); await account.save();", "mapper.map(input, User.class); repository.save(user)"]),
    (770, ["app.post('/upload', upload.single('file'), handler)  # no size limit", "requests.get(url, timeout=None)", "while (items.hasNext()) { process(items.next()); }  // unbounded request work"]),
    (862, ["@app.delete('/admin/users/{id}') def delete(id): return db.delete(id)", "router.post('/ops/rebuild', rebuildHandler)", "@DeleteMapping('/records/{id}') public void remove(@PathVariable long id) { repo.deleteById(id); }"]),
    (841, ["def redeem(code): balance += coupons[code]; return balance", "async function transfer(req) { await debit(req.body.from, req.body.amount); await credit(req.body.to, req.body.amount); }", "if (request.query.confirm) { approveTransfer(request.query.id); }"]),
    (918, ["requests.get(request.args['url'])", "const response = await fetch(req.query.target);", "new URL(request.getParameter('url')).openConnection().getInputStream();"]),
    (16, ["app.config['DEBUG'] = True; app.config['CORS_ALLOW_ALL_ORIGINS'] = True", "server.use(cors({origin: '*', credentials: true}));", "management.endpoints.web.exposure.include=*\nserver.error.include-message=always"]),
    (1059, ["app.get('/v1/orders', handler); app.get('/v2/orders', oldHandler);  # retired route stays active", "router.route('/internal/debug').get(debugHandler)", "@GetMapping('/legacy/v1/export') public Object exportAll() { return service.exportAll(); }"]),
    (444, ["const data = await fetch(partnerUrl).then(r => r.json()); db.save(data);", "response = requests.get(vendor_url); return response.json()", "Object value = mapper.readValue(externalResponse, Object.class); repository.save(value);"]),
    (829, ["requests.get('https://untrusted.example/package.whl');", "dependencies { implementation 'org.example:library:latest' }", "npm install https://unknown.example/archive.tgz"]),
    (327, ["cipher = DES.new(key, DES.MODE_ECB)", "MessageDigest.getInstance('MD5').digest(password)", "crypto.createCipheriv('des-ecb', key, null)"]),
    (89, ["sql = 'SELECT * FROM users WHERE id=' + user_id; db.execute(sql)", "res.send('<div>' + req.query.name + '</div>');", "os.system('ping ' + host)"]),
    (502, ["return pickle.loads(payload)", "ObjectInputStream(input).readObject()", "yaml.load(request.data, Loader=yaml.Loader)"]),
    (778, ["except Exception: pass  # security failure is not recorded", "catch (Exception ignored) { return null; }", "logger.info('request complete')  # no security event details"]),
    (703, ["except Exception: return {'ok': True}  # fail open", "try { commit(); } catch (Exception e) { return SUCCESS; }", "if (error) { continue; }  // inconsistent partial update"]),
    (22, ["open('/srv/files/' + request.args['name'])", "res.sendFile(req.query.path)", "new File(baseDir, request.getParameter('file'))"]),
    (614, ["response.setHeader('Set-Cookie', 'sid=' + sid)", "cookie.setSecure(false); cookie.setHttpOnly(false);", "app.use(cors({origin: '*', credentials: true}));"]),
]

SAFE_CASES = [
    (89, ["db.execute('SELECT * FROM users WHERE id = ?', (user_id,))", "stmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); stmt.setInt(1, id)"]),
    (79, ["element.textContent = user_input", "return render_template('profile.html', name=user_input)"]),
    (918, ["if parsed.hostname not in ALLOWED_HOSTS: raise ValueError('destination not allowed')", "fetch('/api/items/' + encodeURIComponent(item_id))"]),
    (639, ["if order.owner_id != current_user.id: raise Forbidden()", "return repository.findByOwnerAndId(user.id, order_id)"]),
    (16, ["app.config['DEBUG'] = False; app.config['SESSION_COOKIE_SECURE'] = True", "server.use(cors({origin: ['https://app.example'], credentials: true}));"]),
    (502, ["return json.loads(payload)", "return yaml.safe_load(payload)"]),
    (770, ["@app.post('/upload') @limit_content_length(1048576) def upload(): ...", "requests.get(url, timeout=(2, 5))"]),
    (327, ["hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)", "MessageDigest.getInstance('SHA-256').digest(input)"]),
]


def clean_benchmark(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    source = re.sub(r"(?m)^\s*//.*$", " ", source)
    source = re.sub(r"\bBenchmarkTest\d+\b", "BenchmarkCase", source)
    source = re.sub(r"/(?:pathtraver|sqli|xss|cmdi|crypto|hash|weakrand|trustbound|securecookie|ldapi|xpathi)-\d+/", "/case/", source, flags=re.I)
    source = re.sub(r"(?m)^\s*package\s+[^;]+;\s*$", "", source)
    return re.sub(r"\n{3,}", "\n\n", source).strip()


def row(code: str, language: str, vulnerable: bool, cwe: int | None, provenance: str, source_id: str, group: str, synthetic: bool) -> dict:
    code = code.strip()
    ow = OWASP_CWE.get(cwe or -1, ()) if vulnerable else ()
    api = API_CWE.get(cwe or -1, ()) if vulnerable else ()
    digest = hashlib.sha256((code + "\0" + str(cwe) + "\0" + str(vulnerable)).encode()).hexdigest()[:16]
    return {"record_id": digest, "code": code, "language": language, "label": "vulnerable" if vulnerable else "safe", "cwe": cwe or "", "owasp_categories": ";".join(ow), "api_categories": ";".join(api), "provenance": provenance, "source_id": source_id, "split_group": group, "synthetic": bool(synthetic)}


def build(benchmark: Path, teacher_csv: Path | None, output: Path) -> pd.DataFrame:
    results = benchmark / "expectedresults-1.2.csv"
    source_root = benchmark / "src/main/java/org/owasp/benchmark/testcode"
    if not results.is_file() or not source_root.is_dir():
        raise FileNotFoundError("BenchmarkJava esperado con expectedresults-1.2.csv y testcode/; pase --benchmark-root.")
    rows = []
    with results.open(encoding="utf-8-sig", newline="") as stream:
        for test, category, expected, cwe_text in csv.reader(line for line in stream if not line.startswith("#")):
            code_path = source_root / f"{test}.java"
            if not code_path.is_file():
                continue
            code = clean_benchmark(code_path.read_text(encoding="utf-8", errors="replace"))
            rows.append(row(code, "Java", expected.lower() == "true", int(cwe_text), "OWASP Benchmark Java 1.2", test, f"BenchmarkJava:{category}", False))

    if teacher_csv and teacher_csv.is_file():
        teacher = pd.read_csv(teacher_csv)
        for i, item in teacher.drop_duplicates("Code Snippet").iterrows():
            kind = str(item["Vulnerability Type"]).strip().lower()
            cwe = 89 if kind in {"sqli", "sql injection"} else 79 if kind == "xss" else None
            if cwe:
                rows.append(row(str(item["Code Snippet"]), "JavaScript" if cwe == 79 else "Python", True, cwe, "Dataset profesor (muestra deduplicada)", f"teacher:{i}", f"teacher:{kind}", False))

    # Casos sintéticos explícitos: soporte de etiquetas ausentes en el Benchmark;
    # no se incluyen en la métrica de prueba independiente.
    for cwe, examples in API_CASES:
        for idx, code in enumerate(examples):
            rows.append(row(code, "mixed", True, cwe, "synthetic-controlled", f"synthetic:vuln:{cwe}:{idx}", f"synthetic:CWE-{cwe}", True))
    for cwe, examples in SAFE_CASES:
        for idx, code in enumerate(examples):
            rows.append(row(code, "mixed", False, cwe, "synthetic-controlled", f"synthetic:safe:{cwe}:{idx}", f"synthetic:safe:{cwe}", True))

    data = pd.DataFrame(rows, columns=SCHEMA).drop_duplicates(subset=["code", "label", "cwe"], keep="first").reset_index(drop=True)
    data.to_csv(output, index=False, encoding="utf-8")
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--teacher-csv", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "data/vulnerabilities.csv")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = build(args.benchmark_root, args.teacher_csv, args.output)
    print(f"Escritos {len(data)} registros: {data.label.value_counts().to_dict()}")
    print("Fuentes:", data.provenance.value_counts().to_dict())


if __name__ == "__main__":
    main()
