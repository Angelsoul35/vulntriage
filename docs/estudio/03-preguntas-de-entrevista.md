# 03 — Preguntas de entrevista

Preguntas típicas sobre este proyecto y cómo responderlas con seguridad.
Practica diciéndolas en voz alta en inglés también.

## Sobre el enfoque

**¿Por qué no ordenar por CVSS?**
Porque CVSS mide severidad en abstracto, sin entorno. Un 9,8 aislado no es más
urgente que un 6,1 expuesto a internet que procesa pagos. Combino severidad técnica
(CVSS + madurez de exploit) con riesgo ambiental (exposición, criticidad, datos)
para reordenar por riesgo real, como SSVC/EPSS.

**¿Cómo garantizas que una prioridad se pueda defender?**
Con un modelo **aditivo y descomponible**: el resultado lleva la lista de factores
con puntos y razones. Puedo explicar "por qué es P1" línea a línea, y si un factor
está mal, se corrige y recalcula.

**¿Por qué reglas y no un modelo aprendido?**
Porque la priorización debe ser auditable y ajustable por el equipo, el
conocimiento de dominio es durable (sin deriva), y no hay un ground truth de
prioridad correcta: es una decisión de política, no una predicción.

## Sobre la capa de LLM

**¿Dónde usas el LLM y por qué solo ahí?**
Solo para redactar la nota de remediación. La prioridad y el SLA son
deterministas. Así el ranking es reproducible y offline; el LLM mejora la
redacción, con respaldo de plantilla si no hay proveedor. Cada nota marca si vino
del LLM o de la plantilla.

## Sobre el modelo

**¿Qué pasa si el CVSS es 10 pero el activo está aislado y sin exploit?**
Suma 40 por CVSS, 0 por exploit, 0 por exposición/criticidad/datos → 40 → P2/P3
según umbral, no P1. El contexto baja la urgencia, que es el objetivo.

**¿Cómo añadirías EPSS (probabilidad de explotación)?**
Como un `Factor` más en el modelo aditivo: el diseño lo absorbe sin reestructurar,
y queda explícito y explicable.

## Pregunta trampa

**Tu modelo aditivo no captura interacciones (p. ej. expuesto Y weaponizado juntos
peor que la suma). ¿No es una limitación?**
Sí, es consciente. Prefiero la transparencia de la suma a la opacidad de una
multiplicación. Si una interacción es real y relevante, la añado como un factor
explícito propio (revisado), no escondida en una fórmula. Para una decisión que hay
que defender ante quien la ejecuta, explicable gana a ingenioso.
