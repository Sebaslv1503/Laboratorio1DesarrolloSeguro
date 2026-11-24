# Arquitectura

1. **Descubrimiento:** enumera fuentes Java/Python/JavaScript/TypeScript y configuraciones seleccionadas; omite dependencias, entornos, `.git`, build output y archivos de más de 1 MB.
2. **Microservicios:** busca manifests de servicio en ancestros; si no hay manifest, asocia al proyecto raíz.
3. **Características:** TF-IDF de tokens, caracteres y señales estáticas de código/configuración.
4. **Clasificación:** modelo binario vulnerable/seguro; si el modelo marca riesgo, modelos multietiqueta estiman categorías OWASP/API con umbral configurado.
5. **Evidencia:** señales de texto apuntan a una línea y posible CWE. La evidencia complementa la predicción y puede ser imprecisa.
6. **Salidas:** consola, `analysis.json` y `analysis.html`; todos los hallazgos quedan como candidatos de revisión.

La severidad estimada deriva de la categoría y no de la probabilidad. No se confirma vulnerabilidad, no se calcula CVSS y no se analiza flujo de datos entre archivos/servicios.
