from copy import deepcopy
import unittest
from key_mount_policy import validate_key_mount


class KeyMountPolicyTest(unittest.TestCase):
    def setUp(self):
        self.source = {"type": "bind", "source": "${SECURITY_KEYS_PATH:?required}",
                       "read_only": True, "bind": {"create_host_path": False}}
        self.rendered = {"type": "bind", "read_only": True, "bind": {"create_host_path": False}}

    def test_explicit_false(self):
        validate_key_mount(self.source, self.rendered)

    def test_false_omitted_by_older_compose(self):
        del self.rendered["bind"]["create_host_path"]
        validate_key_mount(self.source, self.rendered)

    def test_empty_bind_omitted_by_older_compose(self):
        del self.rendered["bind"]
        validate_key_mount(self.source, self.rendered)

    def test_source_must_declare_false(self):
        del self.source["bind"]["create_host_path"]
        with self.assertRaises(AssertionError):
            validate_key_mount(self.source, self.rendered)

    def test_creation_enabled_is_rejected(self):
        for value in (True, None, "false", 0):
            with self.subTest(value=value):
                rendered = deepcopy(self.rendered)
                rendered["bind"]["create_host_path"] = value
                with self.assertRaises(AssertionError):
                    validate_key_mount(self.source, rendered)

    def test_read_write_is_rejected(self):
        self.rendered["read_only"] = False
        with self.assertRaises(AssertionError):
            validate_key_mount(self.source, self.rendered)

    def test_fallback_is_rejected(self):
        self.source["source"] = "${SECURITY_KEYS_PATH:-../secrets}"
        with self.assertRaises(AssertionError):
            validate_key_mount(self.source, self.rendered)


if __name__ == "__main__":
    unittest.main()
