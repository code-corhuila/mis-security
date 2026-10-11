import json
import os
from pathlib import Path
import subprocess
import yaml
from key_mount_policy import validate_key_mount


root = Path(__file__).resolve().parents[1]
source = yaml.safe_load((root / "deploy/compose.yml").read_text(encoding="utf-8"))
source_mount = next(v for v in source["services"]["security"]["volumes"] if v["target"] == "/run/keys")
base = ["docker", "compose", "-f", str(root / "tests/compose.keypaths.yml")]
environment = os.environ.copy()
environment.update(PG_DATABASE="ci_only", SECURITY_APP_PASSWORD="ci-only-not-a-secret",
                   SECURITY_KEY_ID="ci-key", SECURITY_BOOTSTRAP_ENABLED="false")
environment.pop("SECURITY_KEYS_PATH", None)
for name in ("dev", "qa", "main"):
    args = base + ["--env-file", str(root / "env" / (name + ".env.example"))]
    result = subprocess.run(args + ["config", "--format", "json"], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, "Configuracion de plantilla invalida: " + name
    model = json.loads(result.stdout)
    mount = next(v for v in model["services"]["security"]["volumes"] if v["target"] == "/run/keys")
    expected = root / "secrets"
    if name != "dev":
        expected = expected / name
    assert Path(mount["source"]).resolve() == expected.resolve(), "Ruta incorrecta: " + name
    validate_key_mount(source_mount, mount)
    empty = environment | {"SECURITY_KEYS_PATH": ""}
    result = subprocess.run(args + ["config", "--quiet"], env=empty, capture_output=True, text=True)
    assert result.returncode != 0, "Ruta vacia aceptada: " + name
missing = base + ["--env-file", str(root / "tests/keypaths.env"), "config", "--quiet"]
result = subprocess.run(missing, env=environment, capture_output=True, text=True)
assert result.returncode != 0, "Ruta ausente aceptada."
print("PASS: plantillas dev/qa/main y rechazo de ruta ausente/vacia, sin claves ni motores reales.")
