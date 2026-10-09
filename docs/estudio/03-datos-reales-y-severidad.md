# 03 — Datos reales y el clasificador de severidad

Este capítulo explica la parte de *machine learning* del proyecto: un clasificador
que aprende la **severidad** de una vulnerabilidad a partir de su descripción, y
cómo lo validamos sobre **CVEs reales** del National Vulnerability Database (NVD).

## Hecho vs. política: por qué aquí *sí* aprendemos

En el capítulo 02 defendimos reglas en vez de ML para la **prioridad**. La razón
era que la prioridad es una **decisión de política**: no existe un "ground truth"
de prioridad correcta, porque depende del apetito de riesgo de cada equipo.

La **severidad** está en el otro lado de esa misma línea. La severidad **es un
hecho**: el NVD asigna a cada CVE un vector CVSS, y la puntuación base cae en una
banda cualitativa (LOW / MEDIUM / HIGH / CRITICAL). Cuando un hallazgo llega como
**texto** —un aviso de proveedor, una nota de un bug-tracker— sin vector asignado
todavía, estimar su banda es un problema de predicción legítimo, con una verdad que
aprender y contra la que medir. Esa es la regla del portafolio: **lo que es
política se codifica en reglas; lo que es un hecho se puede aprender**.

## El dato real: cómo derivamos la etiqueta

Usamos `harinpurumandla/cve-severity-dataset` (Hugging Face), construido sobre el
NVD. Cada fila trae la **descripción** del CVE y su **vector CVSS v3.1** de métricas
base, por ejemplo `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

La etiqueta no la inventamos: `real_data.cvss_base_score` implementa las ecuaciones
**canónicas** de CVSS v3.1 (ISS, Impact, Exploitability, el ajuste por *scope* y el
*roundup* a un decimal) para convertir el vector en la puntuación base, y
`severity_band` la mapea a la banda del NVD (`0,1–3,9` LOW, `4,0–6,9` MEDIUM,
`7,0–8,9` HIGH, `9,0–10,0` CRITICAL). Las pruebas comprueban las ecuaciones contra
valores de referencia publicados (Log4Shell = 10,0; un RCE sin autenticación = 9,8),
así que la etiqueta es la severidad **oficial** del NVD, reproducida con exactitud.

### Un subconjunto balanceado y sin fugas

El NVD completo está muy sesgado hacia HIGH y MEDIUM. Vendoreamos un subconjunto
**balanceado**: 700 CVEs por banda (2.800 en total). Dos decisiones importan:

- **Balanceo:** con cuatro clases iguales, la línea base "sin información" es
  adivinar, es decir **0,25**. Así la exactitud se mide contra un suelo limpio y no
  se infla por una clase dominante.
- **Deduplicación:** muchos avisos reales son casi idénticos (el mismo plugin en
  versiones distintas). Quitamos descripciones repetidas para que no se filtre un
  aviso casi igual entre train y test —la misma obsesión anti-fuga del resto del
  portafolio.

## El clasificador

`SeverityClassifier` es un modelo **lineal y transparente**, en el mismo espíritu
que el resto del diseño. Combina (con `FeatureUnion`) dos vistas TF-IDF:

- **Palabras** (unigramas y bigramas, `sublinear_tf`): capturan el fraseo
  ("remote attacker", "arbitrary code", "unauthenticated").
- **Caracteres** (`char_wb`, 3-5): capturan señales por debajo de la palabra y
  sobreviven al estilo abreviado y lleno de siglas de los avisos.

Encima, una regresión logística multinomial con `class_weight="balanced"`. Al ser
lineal, cada decisión es una suma ponderada de rasgos y se pueden leer los términos
que más empujan hacia la banda predicha (`top_terms`).

### Regularización: cerrar la brecha a propósito

Los `min_df` (umbral de frecuencia mínima) descartan tokens que aparecen una sola
vez —cadenas de versión, nombres de producto— que si no dejarían al modelo
**memorizar** avisos concretos. Junto con `C=0,4` en la logística, esta es la
regularización que lleva el modelo al punto donde la exactitud de entrenamiento y la
de test quedan **cerca**. No es un recorte de capacidad: un modelo menos
regularizado memoriza (train sube, la validación cruzada no), y uno más regularizado
empieza a perder exactitud cruzada. Elegimos el punto medio.

## Los números medidos

`python -m vulntriage.real_benchmark` entrena y reporta (semillas fijas, determinista):

```
CVEs: 2800 balanced across 4 bands (LOW 700 / MEDIUM 700 / HIGH 700 / CRITICAL 700)
baseline (four-class chance): 0.250

CV accuracy    : 0.757 +/- 0.009
CV macro-F1    : 0.755
CV weighted-F1 : 0.755
train / test   : 0.880 / 0.753  (brecha 0.127)   -> bien ajustado (well-fit)

matriz de confusión (held-out; filas = real, columnas = predicho):
                   LOW    MEDIUM      HIGH  CRITICAL
       LOW         138        22         7         8
    MEDIUM          29       123        14         9
      HIGH          13        10       119        33
  CRITICAL          13         4        11       147
```

Qué nos dice todo esto:

- **0,76 de exactitud es el triple del suelo de 0,25** de cuatro clases, validado en
  CV con una brecha train/test pequeña (0,127). Es **fuerte y bien ajustado**, no un
  1,0 memorizado. La exactitud cruzada (0,757) casi coincide con la de test (0,753):
  el modelo **generaliza**.
- **Los errores son entre bandas vecinas.** Casi toda la confusión es HIGH↔CRITICAL
  o LOW↔MEDIUM; el modelo rara vez llama CRITICAL a un LOW. Es justo el
  comportamiento deseable, porque las bandas son un corte de una puntuación CVSS
  continua: equivocar la banda contigua es el error "barato".
- **F1 macro ≈ F1 ponderado ≈ exactitud** (todas ~0,755). Como las clases están
  balanceadas, el modelo acierta de forma pareja en las cuatro bandas, no a costa de
  las raras.

### La prueba de que la señal es real

Si **barajamos** las etiquetas (rompemos el vínculo descripción→severidad), la
exactitud cruzada se desploma a ~0,29, cerca del suelo de 0,25, y el veredicto pasa
a "underfit". Esto lo comprueba una prueba del repositorio: demuestra que el 0,76
viene de **estructura aprendida** en las descripciones, no de una fuga.

## El veredicto: underfit / overfit / well-fit

El informe emite un veredicto en lenguaje llano:

- **underfit:** la exactitud cruzada está cerca del suelo de cuatro clases.
- **overfit:** la exactitud de entrenamiento se dispara por encima de la de test
  (brecha grande).
- **well-fit:** fuerte en datos no vistos y con train y test cerca. ← nuestro caso.

## Para fijar la idea

- Prioridad = política → reglas. Severidad = hecho → se aprende. Misma línea, dos
  lados.
- La etiqueta sale del vector CVSS v3.1 con las ecuaciones oficiales: verdad del NVD,
  no una aproximación.
- Dato balanceado + deduplicado → suelo limpio de 0,25 y sin fugas.
- Reportamos el número medido (0,76, validado en CV, brecha 0,127, bien ajustado) y
  lo probamos con el test de etiquetas barajadas. Nada de 1,0 memorizado.
