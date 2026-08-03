from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import EncryptedField
from settings.utils.oidc import (
    OIDCDiscoveryError, get_oidc_issuer, normalize_oidc_url,
)
from .base import OrgListField

__all__ = [
    'OIDCSettingSerializer', 'KeycloakSettingSerializer', 'OIDCDiscoverySerializer',
]


class CommonSettingSerializer(serializers.Serializer):
    PREFIX_TITLE = _('OIDC')
    # OpenID 公有配置参数 (version <= 1.5.8 或 version >= 1.5.8)
    BASE_SITE_URL = serializers.URLField(
        required=False, allow_null=True, allow_blank=True,
        max_length=1024, label=_('Base site URL'),
        help_text=_("The current site's URL is used to construct the callback address")
    )
    AUTH_OPENID_CLIENT_ID = serializers.CharField(
        required=False, max_length=1024, label=_('Client Id')
    )
    AUTH_OPENID_CLIENT_SECRET = EncryptedField(
        required=False, max_length=1024, label=_('Client Secret')
    )
    AUTH_OPENID_CLIENT_AUTH_METHOD = serializers.ChoiceField(
        default='client_secret_basic',
        choices=(
            ('client_secret_basic', 'Client Secret Basic'),
            ('client_secret_post', 'Client Secret Post')
        ),
        label=_('Request method')
    )
    AUTH_OPENID_SHARE_SESSION = serializers.BooleanField(required=False, label=_('Share session'))
    AUTH_OPENID_IGNORE_SSL_VERIFICATION = serializers.BooleanField(
        required=False, default=False, label=_('Ignore SSL verification')
    )
    AUTH_OPENID_USER_ATTR_MAP = serializers.JSONField(
        required=True, label=_('User attribute'),
        help_text=_(
            "User attribute mapping, where the `key` is this system user attribute name "
            "and the `value` is the OIDC service user attribute name"
        )
    )
    AUTH_OPENID_PKCE = serializers.BooleanField(required=False, label=_('Enable PKCE'))
    AUTH_OPENID_CODE_CHALLENGE_METHOD = serializers.ChoiceField(
        default='S256', label=_('Code challenge method'),
        choices=(('S256', 'S256'), ('plain', 'Plain'))
    )

    def get_config_value(self, attrs, name, default=None):
        if name in attrs:
            return attrs[name]
        if isinstance(self.instance, dict):
            return self.instance.get(name, default)
        return default

    def validate_AUTH_OPENID_USER_ATTR_MAP(self, value):
        username_attr = value.get('username') if isinstance(value, dict) else None
        if not isinstance(username_attr, str) or not username_attr.strip():
            raise serializers.ValidationError(_('Username attribute mapping is required'))
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        enabled = self.get_config_value(attrs, 'AUTH_OPENID', False)
        if not enabled:
            return attrs

        client_id = self.get_config_value(attrs, 'AUTH_OPENID_CLIENT_ID')
        if not client_id:
            raise serializers.ValidationError({
                'AUTH_OPENID_CLIENT_ID': _('Client ID is required when OIDC is enabled')
            })

        scopes = self.get_config_value(attrs, 'AUTH_OPENID_SCOPES', '') or ''
        if 'openid' not in scopes.split():
            raise serializers.ValidationError({
                'AUTH_OPENID_SCOPES': _('OIDC scopes must include openid')
            })

        config = dict(self.instance) if isinstance(self.instance, dict) else {}
        config.update(attrs)
        keycloak_enabled = config.get('AUTH_OPENID_KEYCLOAK', False)
        try:
            issuer = get_oidc_issuer(config)
        except OIDCDiscoveryError as exc:
            field = 'AUTH_OPENID_SERVER_URL' if keycloak_enabled else 'AUTH_OPENID_PROVIDER_ENDPOINT'
            if keycloak_enabled and not config.get('AUTH_OPENID_REALM_NAME'):
                field = 'AUTH_OPENID_REALM_NAME'
            raise serializers.ValidationError({field: str(exc)}) from exc

        if keycloak_enabled:
            attrs['AUTH_OPENID_SERVER_URL'] = normalize_oidc_url(
                config['AUTH_OPENID_SERVER_URL'], _('Keycloak server URL'),
                strip_trailing_slash=True,
            )
            attrs['AUTH_OPENID_REALM_NAME'] = config['AUTH_OPENID_REALM_NAME'].strip()
        else:
            attrs['AUTH_OPENID_PROVIDER_ENDPOINT'] = issuer
            required_endpoints = [
                'AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT',
                'AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT',
                'AUTH_OPENID_PROVIDER_JWKS_ENDPOINT',
            ]
            include_claims = config.get('AUTH_OPENID_ID_TOKEN_INCLUDE_CLAIMS', False)
            if not include_claims:
                required_endpoints.append('AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT')
            errors = {
                name: _('This field is required when OIDC is enabled')
                for name in required_endpoints if not config.get(name)
            }
            if errors:
                raise serializers.ValidationError(errors)
        return attrs


class KeycloakSettingSerializer(CommonSettingSerializer):
    # OpenID 旧配置参数 (version <= 1.5.8 (discarded))
    AUTH_OPENID_KEYCLOAK = serializers.BooleanField(
        label=_("Use Keycloak"), required=False, default=False,
        help_text=_(
            "Use Keycloak as the OpenID Connect server, or use standard OpenID Connect Protocol"
        )
    )
    AUTH_OPENID_SERVER_URL = serializers.URLField(
        required=False, max_length=1024, label=_('Server')
    )
    AUTH_OPENID_REALM_NAME = serializers.CharField(
        required=False, max_length=1024, allow_null=True, label=_('Realm name')
    )


class OIDCSettingSerializer(KeycloakSettingSerializer):
    # OpenID 新配置参数 (version >= 1.5.9)
    AUTH_OPENID = serializers.BooleanField(
        required=False, label=_('OIDC'), help_text=_('OpenID Connect')
    )
    AUTH_OPENID_PROVIDER_ENDPOINT = serializers.URLField(
        required=False, max_length=1024, label=_('Provider endpoint'),
        help_text=_(
            "The issuer URL of the OpenID Provider, used to discover its configuration via the "
            "`$PROVIDER_ENDPOINT/.well-known/openid-configuration` endpoint."
        )
    )
    AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT = serializers.URLField(
        required=False, max_length=1024, label=_('Authorization endpoint')
    )
    AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT = serializers.URLField(
        required=False, max_length=1024, label=_('Token endpoint')
    )
    AUTH_OPENID_PROVIDER_JWKS_ENDPOINT = serializers.URLField(
        required=False, max_length=1024, label=_('JWKS endpoint')
    )
    AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT = serializers.URLField(
        required=False, max_length=1024, label=_('Userinfo endpoint')
    )
    AUTH_OPENID_PROVIDER_END_SESSION_ENDPOINT = serializers.URLField(
        required=False, allow_blank=True, max_length=1024, label=_('End session endpoint')
    )
    AUTH_OPENID_PROVIDER_SIGNATURE_ALG = serializers.CharField(
        required=False, default='RS256', max_length=32, label=_('Signature algorithm')
    )
    AUTH_OPENID_PROVIDER_SIGNATURE_KEY = serializers.CharField(
        required=False, max_length=1024, allow_null=True, label=_('Signing key')
    )
    AUTH_OPENID_SCOPES = serializers.CharField(
        required=False, max_length=1024, label=_('Scopes')
    )
    AUTH_OPENID_ID_TOKEN_MAX_AGE = serializers.IntegerField(
        required=False, min_value=60, label=_('ID Token max age (s)')
    )
    AUTH_OPENID_ID_TOKEN_INCLUDE_CLAIMS = serializers.BooleanField(
        required=False, label=_('ID Token include claims')
    )
    AUTH_OPENID_USE_STATE = serializers.BooleanField(
        required=False, label=_('Use state')
    )
    AUTH_OPENID_USE_NONCE = serializers.BooleanField(
        required=False, label=_('Use nonce')
    )
    AUTH_OPENID_ALWAYS_UPDATE_USER = serializers.BooleanField(
        required=False, label=_('Always update user')
    )
    OPENID_ORG_IDS = OrgListField()

    def validate_AUTH_OPENID_PROVIDER_SIGNATURE_ALG(self, value):
        value = value.strip().upper()
        if value == 'NONE':
            raise serializers.ValidationError(_('Unsigned ID tokens are not supported'))
        return value


class OIDCDiscoverySerializer(serializers.Serializer):
    AUTH_OPENID_KEYCLOAK = serializers.BooleanField(required=False, default=False)
    AUTH_OPENID_SERVER_URL = serializers.URLField(required=False, max_length=1024)
    AUTH_OPENID_REALM_NAME = serializers.CharField(required=False, max_length=1024)
    AUTH_OPENID_PROVIDER_ENDPOINT = serializers.URLField(required=False, max_length=1024)
    AUTH_OPENID_IGNORE_SSL_VERIFICATION = serializers.BooleanField(required=False, default=False)
    BASE_SITE_URL = serializers.URLField(
        required=False, allow_null=True, allow_blank=True, max_length=1024
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        try:
            attrs['issuer'] = get_oidc_issuer(attrs)
        except OIDCDiscoveryError as exc:
            field = (
                'AUTH_OPENID_SERVER_URL'
                if attrs.get('AUTH_OPENID_KEYCLOAK')
                else 'AUTH_OPENID_PROVIDER_ENDPOINT'
            )
            if attrs.get('AUTH_OPENID_KEYCLOAK') and not attrs.get('AUTH_OPENID_REALM_NAME'):
                field = 'AUTH_OPENID_REALM_NAME'
            raise serializers.ValidationError({field: str(exc)}) from exc
        return attrs
