"""Catálogo de categorías; las relaciones CWE-OWASP son orientativas."""

OWASP_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

API_2023 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Umbrales mínimos de soporte no sintético para considerar una categoría evaluada.
MIN_EVALUATED_TRAIN_SUPPORT = 15
MIN_EVALUATED_TEST_SUPPORT = 3

OWASP_CWE = {
    22: ("A01:2025",), 23: ("A01:2025",), 36: ("A01:2025",),
    269: ("A01:2025",), 276: ("A01:2025",), 352: ("A01:2025",),
    601: ("A01:2025",), 639: ("A01:2025",), 732: ("A01:2025",),
    862: ("A01:2025",), 863: ("A01:2025",), 915: ("A01:2025",),
    918: ("A01:2025",),
    16: ("A02:2025",), 200: ("A02:2025",), 250: ("A02:2025",),
    489: ("A02:2025",), 614: ("A02:2025",), 942: ("A02:2025",),
    1004: ("A02:2025",), 1275: ("A02:2025",),
    829: ("A03:2025",), 1357: ("A03:2025",),
    295: ("A04:2025",), 319: ("A04:2025",), 326: ("A04:2025",),
    327: ("A04:2025",), 328: ("A04:2025",), 330: ("A04:2025",),
    78: ("A05:2025",), 79: ("A05:2025",), 89: ("A05:2025",),
    90: ("A05:2025",), 91: ("A05:2025",), 94: ("A05:2025",),
    95: ("A05:2025",), 96: ("A05:2025",), 113: ("A05:2025",),
    116: ("A05:2025",), 611: ("A05:2025",), 643: ("A05:2025",),
    943: ("A05:2025",), 1336: ("A05:2025",),
    841: ("A06:2025",),
    287: ("A07:2025",), 306: ("A07:2025",), 347: ("A07:2025",),
    521: ("A07:2025",), 522: ("A07:2025",), 798: ("A07:2025",),
    345: ("A08:2025",), 353: ("A08:2025",), 444: ("A08:2025",),
    501: ("A08:2025",), 502: ("A08:2025",),
    778: ("A09:2025",),
    209: ("A10:2025",), 703: ("A10:2025",), 770: ("A10:2025",),
}

API_CWE = {
    639: ("API1:2023",), 862: ("API1:2023", "API5:2023"), 863: ("API1:2023", "API5:2023"),
    287: ("API2:2023",), 306: ("API2:2023",), 347: ("API2:2023",),
    521: ("API2:2023",), 522: ("API2:2023",), 798: ("API2:2023",),
    200: ("API3:2023",), 915: ("API3:2023",), 1321: ("API3:2023",),
    400: ("API4:2023",), 770: ("API4:2023",), 1333: ("API4:2023",),
    841: ("API6:2023",),
    918: ("API7:2023",),
    16: ("API8:2023",), 250: ("API8:2023",), 489: ("API8:2023",),
    614: ("API8:2023",), 732: ("API8:2023",), 942: ("API8:2023",),
    1004: ("API8:2023",), 1275: ("API8:2023",),
    1059: ("API9:2023",),
    295: ("API10:2023",), 345: ("API10:2023",), 444: ("API10:2023",),
}

REMEDIATION = {
    "A01:2025": "Aplicar autorización en servidor para cada recurso y normalizar rutas antes de usarlas.",
    "A02:2025": "Endurecer configuración, limitar orígenes y desactivar opciones de depuración en despliegues.",
    "A03:2025": "Fijar dependencias, verificar procedencia e integridad de artefactos y proteger el pipeline.",
    "A04:2025": "Usar primitivas criptográficas modernas y gestionar secretos fuera del código.",
    "A05:2025": "Validar entradas y preferir consultas parametrizadas, codificación de salida y APIs seguras.",
    "A06:2025": "Revisar los flujos y controles desde el diseño con requisitos de seguridad explícitos.",
    "A07:2025": "Usar autenticación estándar, verificación robusta de identidad y gestión segura de sesión.",
    "A08:2025": "Validar integridad y confianza de datos, artefactos y resultados de deserialización.",
    "A09:2025": "Registrar eventos relevantes sin secretos y configurar alertas con cobertura verificable.",
    "A10:2025": "Manejar errores de forma segura, fallar cerrado y preservar consistencia ante excepciones.",
    "API1:2023": "Comprobar que el usuario autenticado puede acceder al objeto solicitado.",
    "API2:2023": "Aplicar controles de autenticación robustos y verificar tokens y credenciales.",
    "API3:2023": "Usar esquemas de entrada/salida explícitos y autorizar cada propiedad sensible.",
    "API4:2023": "Imponer límites de tamaño, tiempo, concurrencia y frecuencia en endpoints.",
    "API5:2023": "Validar privilegios para cada función antes de ejecutarla.",
    "API6:2023": "Proteger flujos sensibles con límites de negocio y controles de abuso.",
    "API7:2023": "Restringir destinos salientes con allowlists y bloquear redes internas sensibles.",
    "API8:2023": "Aplicar configuración segura y desactivar funcionalidades expuestas innecesarias.",
    "API9:2023": "Mantener inventario de APIs, versiones y endpoints, y retirar los obsoletos.",
    "API10:2023": "Validar respuestas de terceros y proteger la comunicación, formatos y límites.",
}
