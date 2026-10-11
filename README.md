# mis-security

Servicio de identidad de MediStock (Medicine Inventory System), HU-SEC-001. Java 17 y Spring Boot 4.0.3. PostgreSQL real, bcrypt y JWT RS256 de una hora. No hay registro publico, refresh tokens ni administracion web de usuarios en esta fase.

## Arquitectura

Tres modulos Maven: security-core contiene modelo y puertos sin Spring; security-adapters implementa JDBC, JWT y HTTP; security-app compone los componentes. JDBC se utiliza para identidad por sus consultas y transacciones pequeñas; JPA sigue previsto para Catalogo e Inventario.

Las migraciones no viven aqui: estan en la carpeta local mis-security-db, cuyo repositorio oficial debe confirmar el docente. La composicion raiz esta en mis-infra-postgres. No modificar CODEOWNERS.

## Ejecutar y probar

Requiere Docker Desktop, PowerShell 7 y las carpetas hermanas mis-infra-postgres, mis-infra-mongo y mis-security-db. Desde mis-infra-postgres:

```powershell
pwsh -NoProfile -File .\scripts\Start-Security.ps1
pwsh -NoProfile -File .\scripts\Test-Security.ps1
pwsh -NoProfile -File .\scripts\Test-SecurityMigrations.ps1
```

Start-Security genera claves RSA y passwords aleatorios solo si no existen, migra el esquema y arranca el contenedor. Conserva cuentas y contrasenas existentes. No reemplaza configuracion parcial. Las claves estan en secrets/ y los passwords en env/dev.env, ignorados por Git.

## Endpoints iniciales

Acceso temporal de diagnostico: http://localhost:58081. Solo se publica con compose.dev.yml; la composicion base no expone la API. Los clientes finales usaran el gateway cuando se implemente.

| Metodo | Ruta | Acceso |
| --- | --- | --- |
| GET | /health | Publico; 200 si PostgreSQL responde |
| POST | /api/v1/auth/login | Credenciales validas de una cuenta activa |
| GET | /api/v1/auth/me | JWT valido y cuenta activa |
| GET | /api/v1/auth/jwks | Solo claves publicas |

Importar postman/security.postman_collection.json. Configurar password localmente desde env/dev.env; la coleccion versionada mantiene password y token vacios. Login guarda accessToken para la siguiente consulta.

| Usuario inicial | Rol | Variable de password local |
| --- | --- | --- |
| admin | ADMIN | BOOTSTRAP_ADMIN_PASSWORD |
| inventario | INVENTORY | BOOTSTRAP_INVENTORY_PASSWORD |
| supervisor | SUPERVISOR | BOOTSTRAP_SUPERVISOR_PASSWORD |
| consulta | CONSULTATION | BOOTSTRAP_CONSULTATION_PASSWORD |

No se usa 1234 ni se almacenan passwords de cuentas en semillas SQL. Bootstrap es idempotente y no reactiva cuentas ni cambia roles/passwords existentes. SECURITY_BOOTSTRAP_ENABLED=false lo desactiva; QA/main requieren aprovisionamiento y claves propias, sin copiar secretos de develop.

## Contrato y limites

Cada JWT lleva sub UUID, iss=mis-security, aud=mis-api, exp, iat, kid y roles conocidos. Se valida firma RS256, expiracion con tolerancia 30 segundos y claims obligatorios. HS256 y tokens sin firma se rechazan. JWKS no publica datos privados; X-User-Role no concede permisos.

Las autoridades ROLE_ se derivan del JWT, con manejadores 401/403. Los endpoints actuales son de autenticacion y consulta propia, disponibles para los cuatro roles; las restricciones de escritura de Catalogo/Inventario/Proveedores se integraran y probaran al implementar esas APIs.

Errores contienen error, message y traceId; la cabecera X-Correlation-Id se conserva o se genera de forma segura. Se rechazan campos JSON desconocidos y cuerpos mayores de 64 KiB. Password no se recorta y no supera 72 bytes UTF-8. Username se normaliza a minusculas sin espacios exteriores.

Pool maximo 10, espera 2 segundos y consultas/socket 5 segundos. Registros JSON correlacionados sin tokens o passwords. Logout del cliente borra su token, no revoca el JWT del servidor. Una desactivacion se verifica en login y me; otras APIs validaran tokens hasta expiracion, segun contrato.

## Validacion y publicacion

Validado localmente el 2026-10-10: 10 pruebas del nucleo/JWT sin fallos; Test-Security paso contra PostgreSQL real con cuatro roles, credenciales invalidas, cuenta inactiva, JWT invalido/vencido, JSON, UTF-8, correlacion, tamaño y persistencia de identidad tras reinicio. Las seis migraciones pasaron creacion, reejecucion sin cambios, rollback total y reconstruccion en una base desechable; no se revirtio develop.

CI compila y ejecuta pruebas en PR a develop/qa, con cancelacion y limite de 10 minutos. El primer PR paso su comprobacion en GitHub; el CI de esta segunda entrega se ejecutara al abrir su PR. El contenedor se ejecuta como usuario sin privilegios.

Rama hu-sec-001-runtime-dev desde develop, despues de integrar hu-sec-001-foundation-dev. Este segundo PR agrega la aplicacion ejecutable, Docker, Postman y esta guia; no vuelve a incluir el nucleo ni los adaptadores ya fusionados. Destino develop; promocion a QA con cherry-pick -x y main con aprobacion del docente. No modificar CODEOWNERS ni realizar commits directos a ramas permanentes.

Documentacion central: [mis-docs](https://github.com/code-corhuila/mis-docs).

## Claves RSA por ambiente

SECURITY_KEYS_PATH es obligatorio, incluso en dev. No tiene fallback: ausente o vacio detiene Compose. El montaje es de solo lectura y create_host_path=false impide crear silenciosamente una carpeta de claves inexistente. Las rutas se resuelven respecto de deploy/compose.yml.

| Archivo local ignorado | Plantilla versionada | Directorio de claves |
| --- | --- | --- |
| env/dev.env | env/dev.env.example | ../secrets |
| env/qa.env | env/qa.env.example | ../secrets/qa |
| env/main.env | env/main.env.example | ../secrets/main |

No copiar claves dev a QA/main. Las plantillas no contienen credenciales y no se usan directamente para arrancar con bootstrap habilitado. El generador scripts/New-Environment.ps1 de mis-infra-postgres crea los archivos reales QA/main y pares RSA independientes. Start-Security genera la ruta dev explicitamente; Set-DevSecurityKeyPath agrega solo esa ruta si falta en una instalacion anterior, sin regenerar claves ni passwords.

Desde mis-infra-postgres, tests/Test-SecurityKeyPaths.ps1 verifica configuracion y rechazo de variable ausente/vacia en los tres ambientes. tests/Test-Environments.ps1 -Runtime verifica arranque, rechazo de tokens entre ambientes y recuperacion de QA. Estas pruebas son locales, no promocion formal ni evidencia de CI de este PR.

CI tambien ejecuta tests/check_key_paths.py sobre las tres plantillas con valores sinteticos. Solo valida modelos y rechazo de configuracion incompleta: no descarga motores, no usa claves reales y no acredita arranque de QA/main. Su ejecucion en GitHub se confirma despues del push; la comprobacion local utiliza el mismo script.

Compatibilidad de CI: algunas versiones de Compose omiten create_host_path=false del JSON. La prueba valida primero el YAML original con PyYAML y exige false explicito; solo entonces acepta la omision en el JSON normalizado. No se modifica el montaje ni se permite crear carpetas. Pruebas de regresion cubren ambas representaciones y rechazan true, rutas con fallback, YAML sin false explicito y montajes de escritura. Para ejecutar: instalar tests/requirements.txt, correr unittest discover en tests y tests/check_key_paths.py.

La omision esta documentada en el [tipo oficial ServiceVolumeBind de compose-go v2.4.7](https://github.com/compose-spec/compose-go/blob/v2.4.7/types/types.go): el booleano utiliza json omitempty. Evidencia local de esta correccion: siete pruebas de regresion y las tres plantillas correctas; ejecucion del nuevo commit en GitHub pendiente del push.
