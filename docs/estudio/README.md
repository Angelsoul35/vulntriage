# Guía de estudio — vulntriage

Esta carpeta es una guía en español para entender vulntriage a fondo. El código,
los comentarios y la documentación técnica están en inglés (nivel B2) a propósito,
para que el proyecto sea creíble y sirva para practicar. Esta guía explica el "por
qué" de cada decisión en tu idioma.

## Orden sugerido de lectura

1. **[01-severidad-no-es-prioridad.md](01-severidad-no-es-prioridad.md)** — por qué
   ordenar por CVSS está mal y cómo el contexto reordena el backlog.
2. **[02-modelo-y-notas.md](02-modelo-y-notas.md)** — el modelo aditivo y
   descomponible, por qué reglas y no ML para la prioridad, y la capa de notas con
   LLM + respaldo.
3. **[03-datos-reales-y-severidad.md](03-datos-reales-y-severidad.md)** — el
   clasificador de severidad aprendido, el dato real del NVD, la validación sin
   fugas y los números medidos (0,76 de exactitud, bien ajustado).
4. **[04-preguntas-de-entrevista.md](04-preguntas-de-entrevista.md)** — preguntas
   típicas y cómo responderlas con seguridad.

## Resumen en una frase

vulntriage prioriza un backlog de vulnerabilidades combinando la severidad técnica
(CVSS + madurez del exploit) con el contexto del activo (expuesto a internet,
criticidad, sensibilidad de datos) en una puntuación aditiva y explicable que da
prioridad P1-P4 y un SLA, más una nota de remediación asistida por LLM con
respaldo offline; y, cuando un hallazgo llega solo como texto, un clasificador
aprendido estima su banda de severidad CVSS a partir de la descripción, validado
sobre CVEs reales del NVD.
