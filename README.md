# mis-security

Seguridad transversal de MediStock (Medicine Inventory System), Grupo 1. Documentacion central en [mis-docs](https://github.com/code-corhuila/mis-docs).

## HU-SEC-001 - Primera entrega

Este PR prepara bibliotecas compilables, no un servicio ejecutable. La aplicacion Spring Boot, la composicion Docker y Postman se incorporan en el siguiente PR. No intentar arrancar esta entrega con spring-boot:run.

- security-core: cuentas, puertos y autenticacion sin dependencias de Spring.
- security-adapters: persistencia JDBC, JWT RS256, contratos HTTP y errores correlacionados.
- Pruebas: credenciales, cuentas inactivas, claims y firmas invalidas, cuatro roles y claves publicas JWKS.

Requiere Java 17 y Maven, o Docker Desktop con contenedores Linux:

```powershell
mvn -B verify
# Alternativa sin instalar Java ni Maven:
docker run --rm --mount "type=bind,source=$($PWD.Path),target=/workspace" -w /workspace maven:3.9.9-eclipse-temurin-17 mvn -B verify
```

No necesita una base de datos para estas pruebas unitarias. La persistencia y los permisos de escritura de las APIs de dominio no se validan con esta entrega.

## Publicacion y configuracion

Rama hu-sec-001-foundation-dev y PR hacia develop dentro de code-corhuila/mis-security. Promocion a QA mediante cherry-pick -x; main requiere aprobacion del docente. No fusionar ramas permanentes entre si ni modificar CODEOWNERS.

CI solo en PR hacia develop/qa, con cancelacion y limite de 10 minutos. No versionar env/*.env, secrets/ ni target/. Las claves y credenciales locales de la implementacion completa permanecen ignoradas y no forman parte de este PR.

La implementacion completa se conserva en hu-sec-001-dev; no usar esa rama para un PR conjunto que exceda el limite de lineas. El segundo PR se preparara desde develop despues de integrar el primero.
