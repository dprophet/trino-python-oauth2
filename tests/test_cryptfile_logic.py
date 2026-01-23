import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

# Mock keyring before import to avoid runtime issues if not installed in env used for checking
# But the user environment has it.
# We'll rely on installed packages if possible, but mocking is safer for unit testing logic.

from trino.oauth2.oauth_client import OAuth2Client
from trino.oauth2.models import ClientCredentialsConfig, ManualUrlsConfig

class TestCryptFileLogic(unittest.TestCase):

    def setUp(self):
        self.mock_config = ClientCredentialsConfig(
            client_id="test_client",
            client_secret="test_secret",
            url_config=ManualUrlsConfig(token_endpoint="http://test.com")
        )

    @patch('keyring.set_keyring')
    @patch('keyrings.cryptfile.cryptfile.CryptFileKeyring')
    def test_init_with_token_storage_password(self, mock_kr_cls, mock_set_keyring):
        mock_kr_instance = MagicMock()
        mock_kr_cls.return_value = mock_kr_instance

        # Simulate Backend set, but NO Env Password
        with patch.dict(os.environ, {"PYTHON_KEYRING_BACKEND": "keyrings.cryptfile.cryptfile.CryptFileKeyring"}):
            if "KEYRING_CRYPTFILE_PASSWORD" in os.environ:
                del os.environ["KEYRING_CRYPTFILE_PASSWORD"]

            client = OAuth2Client(
                config=self.mock_config,
                token_storage_password="password123"
            )

            # Check if keyring key was set to the argument
            self.assertEqual(mock_kr_instance.keyring_key, "password123")
            mock_set_keyring.assert_called_with(mock_kr_instance)

    @patch('keyring.set_keyring')
    @patch('keyrings.cryptfile.cryptfile.CryptFileKeyring')
    def test_precedence_env_over_arg(self, mock_kr_cls, mock_set_keyring):
        mock_kr_instance = MagicMock()
        mock_kr_cls.return_value = mock_kr_instance

        # Simulate Backend set AND Env Password set
        with patch.dict(os.environ, {
            "PYTHON_KEYRING_BACKEND": "keyrings.cryptfile.cryptfile.CryptFileKeyring",
            "KEYRING_CRYPTFILE_PASSWORD": "env_password_value"
        }):
            client = OAuth2Client(
                config=self.mock_config,
                token_storage_password="arg_password_value"
            )

            # Check if keyring key was set to the ENV value, not the arg
            self.assertEqual(mock_kr_instance.keyring_key, "env_password_value")
            mock_set_keyring.assert_called_with(mock_kr_instance)

    @patch('keyring.set_keyring')
    @patch('keyrings.cryptfile.cryptfile.CryptFileKeyring')
    def test_raise_error_if_missing(self, mock_kr_cls, mock_set_keyring):
        # Simulate Backend set, NO Env Password, NO Arg Password
        with patch.dict(os.environ, {"PYTHON_KEYRING_BACKEND": "keyrings.cryptfile.cryptfile.CryptFileKeyring"}):
            if "KEYRING_CRYPTFILE_PASSWORD" in os.environ:
                del os.environ["KEYRING_CRYPTFILE_PASSWORD"]

            with self.assertRaises(RuntimeError) as cm:
                client = OAuth2Client(
                    config=self.mock_config
                )

            self.assertIn("KEYRING_CRYPTFILE_PASSWORD is not set and no token_storage_password provided", str(cm.exception))

if __name__ == '__main__':
    unittest.main()

