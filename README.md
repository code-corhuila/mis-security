# mis-security

Servicio de identidad de MediStock (Medicine Inventory System), HU-SEC-001. Java 17 y Spring Boot 4.0.3. PostgreSQL real, bcrypt y JWT RS256 de una hora. No hay registro publico, refresh tokens ni administracion web de usuarios en esta fase.

## Arquitectura

Tres modulos Maven: security-core contiene modelo y puertos sin Spring; security-adapters implementa JDBC, JWT y HTTP; security-app compone los componentes. JDBC se utiliza para identidad por sus consultas y transacciones pequeñas; JPA sigue previsto para Catalogo e Inventario.

Las migraciones no viven aqui: estan en la carpeta local mis-security-db, cuyo repositorio oficial debe confirmar el docente. La composicion raiz esta en mis-infra-postgres. No modificar CODEOWNERS.

## Ejecutar y probar

Requiere Docker Desktop, PowerShell 7 y las carpetas hermanas mis-infra-postgres, mis-infra-mongo y mis-security-db. Desde mis-infra-postgres:

```powershell
.\scripts\Start-Security.ps1
.\scripts\Test-Security.ps1
.\scripts\Test-SecurityMigrations.ps1
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

CI compila y ejecuta pruebas en PR a develop/qa, con cancelacion y limite de 10 minutos; su ejecucion en GitHub esta pendiente. El contenedor se ejecuta como usuario sin privilegios.

Rama hu-sec-001-dev desde develop; no commits directos a permanentes. Los cambios del servicio superan 400 lineas: separar en aportes revisables antes de publicar. No se realiza commit o push automaticamente.

Documentacion central: [mis-docs](https://github.com/code-corhuila/mis-docs).
