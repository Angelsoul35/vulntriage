# 01 — Severidad no es prioridad

## El error de ordenar por CVSS

La forma "obvia" de triar un backlog es ordenar por la puntuación base CVSS. Pero
CVSS mide la severidad de una vulnerabilidad **en abstracto**: a propósito **no**
tiene en cuenta el entorno. Ordenar solo por CVSS manda al equipo a parchear un 9,8
en una máquina de laboratorio aislada antes que un 6,1 en un sistema expuesto a
internet que procesa pagos. El orden está mal justo donde más importa.

## La idea: severidad + contexto

La prioridad se calcula combinando:

- **Severidad técnica:** la base CVSS, elevada por la **madurez del exploit**
  (ninguno / PoC / funcional / weaponizado).
- **Riesgo ambiental:** ¿el activo está **expuesto a internet**?, ¿su
  **criticidad** de negocio?, ¿qué **sensibilidad de datos** maneja?

Combinarlos reordena el backlog para que cuenten la exposición y el impacto, igual
que los marcos modernos (SSVC de FIRST, priorización informada por EPSS).

## El ejemplo del backlog

- CVSS **6,1** (XSS) expuesto a internet **supera** a un CVSS **7,8** (escalada
  local) en un agente de build aislado y sin exploit.
- Un CVSS **9,8** (RCE) en un host interno queda **por debajo** de dos P1
  expuestos a internet.

Eso es exactamente lo que se quiere: el contexto gana a la severidad cruda.

## Para fijar la idea

- CVSS = severidad en abstracto; no es prioridad.
- Prioridad = severidad técnica (CVSS + exploit) + riesgo ambiental (exposición,
  criticidad, datos).
- Requiere contexto del activo (de un CMDB/inventario): ahí está el valor.
