# scope-lib

Kernel de confianza compartido para el ecosistema de defensa de agentes
(adi-shield, wallet-guard, goal-anchor, trajectory-sentinel).

Define el esquema del *policy store* y del *anchor* (formato + versión),
y la evaluación de alcance de tarea (`evaluate_scope`) con tres criterios:

- **(i)** sub-objetivo en lista autorizada por el usuario
- **(ii)** recurso objetivo en recursos autorizados
- **(iii)** soporte transitivo por transición cerrada, NO irreversible

Reglas de fallo seguro: sin *anchor* activa → `confirm` (nunca `allow`);
acción irreversible sin autorización explícita → `confirm` (nunca `allow` ciego);
versión de esquema distinta → error al cargar (no carga silenciosa).

Es el componente de MAYOR confianza del ecosistema: un bug suyo se propaga
a los tres sensores aunque el proceso nunca caiga. Exige cobertura de casos
borde del esquema y revisión de pares en cambios de formato/versión.

## Licencia

AGPL-3.0-or-later · Autor: Pedro Sordo Martínez (amurlaniakea@gmail.com)
Año: 2026
