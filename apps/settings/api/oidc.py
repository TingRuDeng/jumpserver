from urllib.parse import urljoin

from django.conf import settings
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from common.utils import get_logger
from settings.models import Setting
from settings.utils.oidc import OIDCDiscoveryError, discover_oidc_configuration
from .. import serializers


logger = get_logger(__file__)


class OIDCTestingAPI(GenericAPIView):
    serializer_class = serializers.OIDCDiscoverySerializer
    perm_model = Setting
    rbac_perms = {
        'POST': 'settings.change_auth'
    }

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        config = serializer.validated_data

        try:
            result = discover_oidc_configuration(
                config['issuer'],
                verify=not config.get('AUTH_OPENID_IGNORE_SSL_VERIFICATION', False),
            )
        except OIDCDiscoveryError as exc:
            logger.warning('OIDC provider connection test failed: %s', exc)
            return Response(
                {'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST
            )

        callback_path = reverse(settings.AUTH_OPENID_AUTH_LOGIN_CALLBACK_URL_NAME)
        base_site_url = config.get('BASE_SITE_URL')
        if base_site_url:
            callback_url = urljoin(base_site_url, callback_path)
        else:
            callback_url = request.build_absolute_uri(callback_path)

        return Response({
            'msg': _('Test success'),
            'issuer': result['issuer'],
            'discovery_url': result['discovery_url'],
            'callback_url': callback_url,
            'endpoints': result['endpoints'],
        })
