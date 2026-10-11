# Identidad local de Workflow

La firma pertenece a mis-security. Issue-WorkflowServiceToken.ps1 es una herramienta
local de administracion: solo un operador con acceso a la clave de Seguridad puede
ejecutarla. No es un endpoint remoto ni un flujo client_credentials implementado.
Infraestructura delega su ejecucion y no contiene logica de firma ni rutas privadas.

Despues de New-WorkflowEnvironment.ps1, registrar una sola vez por ambiente:

```powershell
./scripts/Issue-WorkflowServiceToken.ps1 -Environment dev -Register
```

El registro ignorado workflow-identity.json fija subject, servicio, ambiente y kid.
La renovacion rechaza cambios en esa identidad o una clave publica ajena. Solo emite
INVENTORY para mis-workflow; conserva subject y cambia jti. El JWT dura como maximo
3600 segundos y se reemplaza atomicamente; Workflow lo relee en cada llamada.

Para renovar, ejecutar el mismo comando sin -Register antes del vencimiento.
En qa/main registrar y renovar explicitamente cada ambiente: nunca usar dev como
fallback. La renovacion sigue siendo manual; no se ha implementado un temporizador
ni se certifica disponibilidad continua en QA/main. Antes de una aceptacion larga,
renovar; si expira, renovar y reanudar la saga, nunca copiar claves privadas.
Una rotacion de clave/subject requiere un procedimiento separado aprobado.

Este cambio corrige la propiedad del emisor, no convierte el workstation local en
un servicio de identidad remoto. El acceso al host sigue siendo un limite de confianza.
