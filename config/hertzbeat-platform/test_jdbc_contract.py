import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / 'ansible/roles/hertzbeat_platform/filter_plugins/hertzbeat_contract.py'
spec = importlib.util.spec_from_file_location('jdbc_contract', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class JdbcContractTest(unittest.TestCase):
    def test_verify_full_with_owned_ca(self):
        self.assertTrue(module.verified_jdbc('jdbc:postgresql://pg-hertzbeat-rw/hertzbeat?sslmode=verify-full&sslrootcert=/run/secrets/hertzbeat/pg-ca.pem'))

    def test_reject_duplicate_or_bypass_options(self):
        prefix = 'jdbc:postgresql://pg-hertzbeat-rw/hertzbeat?sslmode=verify-full&sslrootcert=/run/secrets/hertzbeat/pg-ca.pem'
        for suffix in ['&sslmode=disable', '&sslfactory=UnsafeFactory', '&sslhostnameverifier=UnsafeVerifier', '&password=sentinel']:
            self.assertFalse(module.verified_jdbc(prefix + suffix))
        self.assertFalse(module.verified_jdbc('jdbc:postgresql://pg-hertzbeat-rw/hertzbeat?sslmode=verify-full'))


if __name__ == '__main__':
    unittest.main()
