def validate_key_mount(source, rendered):
    expression = source.get("source", "")
    if not expression.startswith("${SECURITY_KEYS_PATH:?") or not expression.endswith("}"):
        raise AssertionError("La ruta de claves debe ser obligatoria, sin fallback.")
    for mount in (source, rendered):
        if mount.get("type") != "bind" or mount.get("read_only") is not True:
            raise AssertionError("Las claves requieren bind de solo lectura.")
    if source.get("bind", {}).get("create_host_path") is not False:
        raise AssertionError("El YAML debe declarar create_host_path=false explicitamente.")
    # Compose v2 puede omitir false en JSON; solo se acepta tras verificar el YAML.
    options = rendered.get("bind") or {}
    if options.get("create_host_path", False) is not False:
        raise AssertionError("Compose no debe crear directorios de claves.")
