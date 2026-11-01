import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from phishguard import analyze


class T(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(analyze("https://www.google.com")["verdict"], "LOOKS OK")

    def test_ip(self):
        self.assertGreaterEqual(analyze("http://192.168.1.1/login")["score"], 30)

    def test_brand(self):
        self.assertIn(analyze("http://paypal-secure-login.xyz/verify")["verdict"], ("SUSPICIOUS", "DANGEROUS"))

    def test_typo(self):
        self.assertGreater(analyze("https://paypall.com")["score"], 0)


if __name__ == "__main__":
    unittest.main()
