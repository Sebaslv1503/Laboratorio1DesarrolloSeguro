"""Features léxicas y señales estáticas consumidas por los clasificadores ML."""
from __future__ import annotations

import re

from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer

SIGNALS = {
    "sql_sink": r"(?i)(execute|query|rawQuery|createQuery)\s*\(?.{0,100}(select|insert|update|delete)",
    "sql_parameterized": r"(?i)(prepareStatement|execute\([^)]*\?|execute\([^)]*,\s*\(|text\([^)]*:[a-z_])",
    "html_sink": r"(?i)(innerHTML|outerHTML|document\.write|\.html\s*\(|res\.send\s*\().{0,100}(req|request|input|param|user)",
    "safe_text_sink": r"(?i)(textContent|innerText|escape\(|sanitize\()",
    "shell_sink": r"(?i)(os\.system|subprocess\.(run|Popen|call)|Runtime\.getRuntime|exec\s*\().{0,120}(input|request|param|host)",
    "shell_safe": r"(?i)(shell\s*=\s*False|ProcessBuilder|subprocess\.(run|Popen)\(\s*\[)",
    "path_sink": r"(?i)(sendFile|readFile|FileInputStream|open\s*\().{0,100}(path|file|param|request)",
    "path_guard": r"(?i)(normalize\(\)|realpath|resolve\(\)|startsWith\(|is_relative_to)",
    "weak_crypto": r"(?i)\b(md5|sha-?1|des|rc4|ecb)\b",
    "safe_crypto": r"(?i)\b(argon2|bcrypt|scrypt|sha-?256|sha-?512|aes/gcm)\b",
    "unsafe_deserialization": r"(?i)(pickle\.loads|ObjectInputStream|yaml\.load\s*\(|readObject\s*\()",
    "debug_enabled": r"(?i)(debug\s*=\s*true|DEBUG\s*:\s*true|exposure\.include\s*=\s*\*|allowallorigins|origin\s*:\s*['\"]\*['\"]|privileged\s*:\s*true|user\s+root\b)",
    "external_request": r"(?i)(requests\.(get|post|request)|fetch\s*\(|openConnection\s*\(|axios\.(get|post)|urllib\.request)",
    "insecure_tls": r"(?i)(verify\s*=\s*false|rejectunauthorized\s*:\s*false|insecure_skip_verify|trustallcerts)",
    "hardcoded_secret": r"(?i)(password|secret|api_?key|jwt_?secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "owner_check": r"(?i)(owner_?id|findByOwner|current_user\.id|principal\.getName|authorize|isAuthorized)",
    "auth_check": r"(?i)(authenticate|verifyToken|jwt\.verify|hasRole|isAuthenticated|@PreAuthorize)",
    "resource_limit": r"(?i)(rate.?limit|max.?content.?length|timeout\s*=|maxRequestSize|throttle)",
    "mass_assignment": r"(?i)(Object\.assign\s*\([^,]+,\s*(req|request)\.|\.update\s*\(\s*(req|request)\.(body|json))",
    "exception_suppressed": r"(?i)(except\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}|catch\s*\([^)]*\)\s*\{\s*return\s+null)",
    "dependency_source": r"(?i)(https?://[^\s'\"]+\.(jar|whl|tgz)|\*\s*\n|latest['\"]|dependency-check|checksum)",
    "security_logging": r"(?i)(audit|security.?event|logger\.(warn|error|info)|logging\.(warning|error|critical))",
}

_COMPILED_SIGNALS = [
    (name, re.compile(pattern.replace("(?i)", "").lower(), re.ASCII))
    for name, pattern in SIGNALS.items()
]
_HTTP_ENDPOINT_RE = re.compile(
    r"(@app\.(get|post|put|delete)|@(get|post|put|delete)mapping|router\.(get|post|put|delete)|app\.(get|post|put|delete))",
    re.ASCII,
)


def pattern_features(texts):
    output = []
    for text in texts:
        lowered = text.lower()
        flags = {name: float(bool(rx.search(lowered))) for name, rx in _COMPILED_SIGNALS}
        flags["line_count"] = min(lowered.count("\n") / 100, 1.0)
        flags["has_http_endpoint"] = float(bool(_HTTP_ENDPOINT_RE.search(lowered)))
        output.append(flags)
    return output


def make_vectorizer():
    token_pattern = r"(?u)\b\w+\b|==|!=|<=|>=|&&|\|\||[{}()\[\];=+\-*/<>.'\"]"
    return FeatureUnion([
        ("word", TfidfVectorizer(lowercase=True, token_pattern=token_pattern, ngram_range=(1, 2), min_df=2, max_features=60000, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char", lowercase=True, ngram_range=(3, 5), min_df=2, max_features=50000, sublinear_tf=True)),
        ("signals", Pipeline([("flags", FunctionTransformer(pattern_features, validate=False)), ("dict", DictVectorizer())])),
    ])
