# 02 — El modelo y las notas

## Un modelo aditivo y descomponible

La puntuación (0-100, con tope) es **aditiva**: cada dimensión aporta un `Factor`
con puntos y una razón, y la puntuación es su suma.

| Factor             | Aporte                                                      |
| ------------------ | ----------------------------------------------------------- |
| CVSS base          | `cvss × 4` (0-40)                                           |
| Madurez de exploit | ninguno 0 · PoC +8 · funcional +16 · weaponizado +24        |
| Criticidad         | baja 0 · media +8 · alta +18                                |
| Sensibilidad datos | ninguna 0 · interna +4 · sensible (PII/PHI/financiera) +12  |
| Expuesto a internet| +15                                                         |

Prioridad y SLA por umbral: `≥70 P1/7d`, `≥45 P2/30d`, `≥25 P3/90d`, si no `P4/180d`.

### ¿Por qué aditivo?

Porque la puntuación debe ser **descomponible**: el resultado lleva la lista exacta
de puntos y razones que la produjeron. Cuando a un responsable le dices "parchea
esto en 7 días", preguntará "¿por qué es P1?", y debes poder responder línea a
línea ("CVSS 9,8 ×4 = 39,2; weaponizado +24; expuesto +15"). Si un factor está mal
(el activo no está expuesto), se señala y la puntuación se recalcula sola. Un
modelo multiplicativo o aprendido sería más difícil de justificar.

## ¿Por qué reglas y no ML?

Tres razones: la priorización debe ser **auditable y ajustable** por el equipo de
seguridad a su apetito de riesgo; los factores codifican conocimiento de dominio
**durable** (no hay deriva); y **no existe un "ground truth"** de prioridad
correcta que aprender — la prioridad es una **decisión de política**, no un hecho
a predecir. Aprender de decisiones pasadas solo codificaría hábitos y sesgos.

## La capa de notas: LLM + respaldo

La prioridad y el SLA los deciden las reglas. El LLM **solo** escribe la frase de
recomendación. El `RemediationAdvisor` manda el hallazgo y su contexto a la cascada
de proveedores; si ninguno responde, usa una nota de plantilla con los mismos
datos. Así la nota siempre existe y el pipeline corre offline. Cada nota marca su
`source` (`llm` o `heuristic`). El LLM mejora la lectura, no es una dependencia.

## Para fijar la idea

- Puntuación aditiva = descomponible, explicable, ajustable.
- Reglas, no ML: auditable, sin deriva, y la prioridad es política, no predicción.
- El LLM solo redacta la nota; con respaldo de plantilla y offline.
