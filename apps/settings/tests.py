import time
from unittest.mock import Mock, patch

from django.core.exceptions import SuspiciousOperation
from django.test import SimpleTestCase, override_settings

from authentication.backends.oidc.utils import (
    _validate_claims, validate_and_return_id_token,
)
from jumpserver.conf import Config
from settings.serializers.auth.oidc import OIDCSettingSerializer
from settings.utils.oidc import (
    OIDCDiscoveryError, build_keycloak_issuer, discover_oidc_configuration,
)


class OIDCConfigurationTest(SimpleTestCase):
    @staticmethod
    def response(data):
        response = Mock()
        response.json.return_value = data
        response.raise_for_status.return_value = None
        return response

    def test_build_keycloak_issuer(self):
        issuer = build_keycloak_issuer(
            'https://Keycloak.EXAMPLE.com/', 'jump server'
        )
        self.assertEqual(
            issuer, 'https://keycloak.example.com/realms/jump%20server'
        )

    def test_discovery_validates_issuer_and_signing_keys(self):
        issuer = 'https://id.example.com/realms/jumpserver'
        client = Mock()
        client.get.side_effect = [
            self.response({
                'issuer': issuer,
                'authorization_endpoint': f'{issuer}/authorize?kc_idp_hint=local',
                'token_endpoint': f'{issuer}/token',
                'jwks_uri': f'{issuer}/certs',
                'userinfo_endpoint': f'{issuer}/userinfo',
                'end_session_endpoint': f'{issuer}/logout',
            }),
            self.response({'keys': [{'kid': 'test', 'kty': 'RSA'}]}),
        ]

        result = discover_oidc_configuration(issuer, http_client=client)

        self.assertEqual(result['issuer'], issuer)
        self.assertEqual(
            result['endpoints']['AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT'],
            f'{issuer}/authorize?kc_idp_hint=local',
        )
        self.assertEqual(client.get.call_count, 2)

    def test_discovery_rejects_mismatched_issuer(self):
        issuer = 'https://id.example.com/realms/jumpserver'
        client = Mock()
        client.get.return_value = self.response({
            'issuer': 'https://id.example.com/realms/other',
            'authorization_endpoint': f'{issuer}/authorize',
            'token_endpoint': f'{issuer}/token',
            'jwks_uri': f'{issuer}/certs',
        })

        with self.assertRaisesRegex(OIDCDiscoveryError, 'does not match'):
            discover_oidc_configuration(issuer, http_client=client)

    def test_discovery_rejects_empty_signing_keys(self):
        issuer = 'https://id.example.com/realms/jumpserver'
        client = Mock()
        client.get.side_effect = [
            self.response({
                'issuer': issuer,
                'authorization_endpoint': f'{issuer}/authorize',
                'token_endpoint': f'{issuer}/token',
                'jwks_uri': f'{issuer}/certs',
            }),
            self.response({'keys': []}),
        ]

        with self.assertRaisesRegex(OIDCDiscoveryError, 'does not contain any keys'):
            discover_oidc_configuration(issuer, http_client=client)

    def test_keycloak_serializer_derives_valid_issuer(self):
        serializer = OIDCSettingSerializer(data={
            'AUTH_OPENID': True,
            'AUTH_OPENID_KEYCLOAK': True,
            'AUTH_OPENID_SERVER_URL': 'https://id.example.com/',
            'AUTH_OPENID_REALM_NAME': 'jumpserver',
            'AUTH_OPENID_CLIENT_ID': 'jumpserver',
            'AUTH_OPENID_SCOPES': 'openid profile email',
            'AUTH_OPENID_USER_ATTR_MAP': {
                'username': 'preferred_username',
                'name': 'name',
                'email': 'email',
            },
        })

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(
            serializer.validated_data['AUTH_OPENID_SERVER_URL'],
            'https://id.example.com',
        )

    def test_keycloak_serializer_requires_realm(self):
        serializer = OIDCSettingSerializer(data={
            'AUTH_OPENID': True,
            'AUTH_OPENID_KEYCLOAK': True,
            'AUTH_OPENID_SERVER_URL': 'https://id.example.com',
            'AUTH_OPENID_CLIENT_ID': 'jumpserver',
            'AUTH_OPENID_SCOPES': 'openid profile email',
            'AUTH_OPENID_USER_ATTR_MAP': {
                'username': 'preferred_username',
            },
        })

        self.assertFalse(serializer.is_valid())
        self.assertIn('AUTH_OPENID_REALM_NAME', serializer.errors)

    def test_convert_keycloak_configuration(self):
        config = Config.convert_keycloak_to_openid({
            'AUTH_OPENID': True,
            'AUTH_OPENID_KEYCLOAK': True,
            'AUTH_OPENID_SERVER_URL': 'https://id.example.com/',
            'AUTH_OPENID_REALM_NAME': 'jumpserver',
        })

        issuer = 'https://id.example.com/realms/jumpserver'
        self.assertEqual(config['AUTH_OPENID_PROVIDER_ENDPOINT'], issuer)
        self.assertEqual(
            config['AUTH_OPENID_PROVIDER_JWKS_ENDPOINT'],
            f'{issuer}/protocol/openid-connect/certs',
        )
        self.assertEqual(config['AUTH_OPENID_PROVIDER_SIGNATURE_ALG'], 'RS256')
        self.assertTrue(config['AUTH_OPENID_PKCE'])


class OIDCTokenValidationTest(SimpleTestCase):
    issuer = 'https://id.example.com/realms/jumpserver'

    @override_settings(
        AUTH_OPENID_PROVIDER_ENDPOINT=issuer,
        AUTH_OPENID_CLIENT_ID='jumpserver',
        AUTH_OPENID_ID_TOKEN_MAX_AGE=600,
        AUTH_OPENID_USE_NONCE=False,
    )
    def test_rejects_same_host_with_different_issuer_path(self):
        now = int(time.time())
        token = {
            'iss': 'https://id.example.com/realms/other',
            'aud': 'jumpserver',
            'exp': now + 300,
            'iat': now,
        }

        with self.assertRaisesRegex(SuspiciousOperation, 'Invalid issuer'):
            _validate_claims(token, validate_nonce=False)

    @override_settings(
        AUTH_OPENID_PROVIDER_ENDPOINT=issuer,
        AUTH_OPENID_PROVIDER_SIGNATURE_ALG='HS256',
        AUTH_OPENID_PROVIDER_SIGNATURE_KEY=None,
        AUTH_OPENID_CLIENT_ID='jumpserver',
        AUTH_OPENID_CLIENT_SECRET='shared-secret',
        AUTH_OPENID_ID_TOKEN_MAX_AGE=600,
        AUTH_OPENID_USE_NONCE=False,
    )
    @patch('authentication.backends.oidc.utils._get_jwks_keys')
    @patch('authentication.backends.oidc.utils.JWS')
    def test_hs256_uses_client_secret(self, jws_class, get_jwks_keys):
        now = int(time.time())
        jws_class.return_value.verify_compact.return_value = {
            'iss': self.issuer,
            'aud': 'jumpserver',
            'exp': now + 300,
            'iat': now,
        }

        validate_and_return_id_token('encoded-token', validate_nonce=False)

        get_jwks_keys.assert_called_once_with('shared-secret')
