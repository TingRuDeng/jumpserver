from urllib.parse import quote, urlsplit, urlunsplit

import requests
from django.utils.translation import gettext_lazy as _


OIDC_ENDPOINT_SETTING_MAP = {
    'AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT': 'authorization_endpoint',
    'AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT': 'token_endpoint',
    'AUTH_OPENID_PROVIDER_JWKS_ENDPOINT': 'jwks_uri',
    'AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT': 'userinfo_endpoint',
    'AUTH_OPENID_PROVIDER_END_SESSION_ENDPOINT': 'end_session_endpoint',
}


class OIDCDiscoveryError(ValueError):
    pass


def normalize_oidc_url(
    value, field_name='URL', *, allow_query=False, strip_trailing_slash=False
):
    value = (value or '').strip()
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise OIDCDiscoveryError(_('{} must be an HTTP or HTTPS URL').format(field_name))
    if parsed.username or parsed.password:
        raise OIDCDiscoveryError(_('{} must not contain credentials').format(field_name))
    if parsed.fragment:
        raise OIDCDiscoveryError(_('{} must not contain a fragment').format(field_name))
    if parsed.query and not allow_query:
        raise OIDCDiscoveryError(_('{} must not contain a query string').format(field_name))

    path = parsed.path.rstrip('/') if strip_trailing_slash else parsed.path
    query = parsed.query if allow_query else ''
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ''))


def build_keycloak_issuer(server_url, realm_name):
    server_url = normalize_oidc_url(
        server_url, _('Keycloak server URL'), strip_trailing_slash=True
    )
    realm_name = (realm_name or '').strip()
    if not realm_name:
        raise OIDCDiscoveryError(_('Keycloak realm is required'))
    if '/' in realm_name:
        raise OIDCDiscoveryError(_('Keycloak realm must not contain a slash'))
    return f'{server_url}/realms/{quote(realm_name, safe="")}'


def get_oidc_issuer(config):
    if config.get('AUTH_OPENID_KEYCLOAK'):
        return build_keycloak_issuer(
            config.get('AUTH_OPENID_SERVER_URL'),
            config.get('AUTH_OPENID_REALM_NAME'),
        )
    return normalize_oidc_url(
        config.get('AUTH_OPENID_PROVIDER_ENDPOINT'), _('OIDC provider endpoint')
    )


def discover_oidc_configuration(issuer, verify=True, timeout=10, http_client=requests):
    issuer = normalize_oidc_url(issuer, _('OIDC issuer'))
    discovery_url = f'{issuer.rstrip("/")}/.well-known/openid-configuration'

    try:
        response = http_client.get(discovery_url, timeout=timeout, verify=verify)
        response.raise_for_status()
        metadata = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise OIDCDiscoveryError(_('Unable to load OIDC discovery document: {}').format(exc)) from exc

    if not isinstance(metadata, dict):
        raise OIDCDiscoveryError(_('OIDC discovery document must be a JSON object'))

    discovered_issuer = normalize_oidc_url(metadata.get('issuer'), _('Discovered OIDC issuer'))
    if discovered_issuer != issuer:
        raise OIDCDiscoveryError(_('OIDC discovery issuer does not match the configured issuer'))

    required_fields = ('authorization_endpoint', 'token_endpoint', 'jwks_uri')
    missing_fields = [name for name in required_fields if not metadata.get(name)]
    if missing_fields:
        raise OIDCDiscoveryError(
            _('OIDC discovery document is missing: {}').format(', '.join(missing_fields))
        )

    endpoints = {}
    for setting_name, metadata_name in OIDC_ENDPOINT_SETTING_MAP.items():
        value = metadata.get(metadata_name)
        if not value:
            continue
        endpoints[setting_name] = normalize_oidc_url(
            value, metadata_name, allow_query=True
        )

    jwks_url = endpoints['AUTH_OPENID_PROVIDER_JWKS_ENDPOINT']
    try:
        response = http_client.get(jwks_url, timeout=timeout, verify=verify)
        response.raise_for_status()
        jwks = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise OIDCDiscoveryError(_('Unable to load OIDC signing keys: {}').format(exc)) from exc

    if not isinstance(jwks, dict) or not isinstance(jwks.get('keys'), list) or not jwks['keys']:
        raise OIDCDiscoveryError(_('OIDC signing keys response does not contain any keys'))

    return {
        'issuer': issuer,
        'discovery_url': discovery_url,
        'endpoints': endpoints,
    }
