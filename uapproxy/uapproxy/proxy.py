# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       url
"""
import functools
from ua_parser import user_agent_parser
import django
from django.conf import settings
from django.core.cache import cache
from django.db.models import F
from hashlib import sha256
import re
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional

from proxy.http import httpStatusCodes
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.common.flag import flags
from proxy.http.parser import HttpParser
from proxy.common.utils import text_
from proxy.http.exception import HttpRequestRejected

import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'uapproxy.settings')
os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', '1')
django.setup()

from policer import models


logger = logging.getLogger(__name__)

flags.add_argument(
    '--uapproxy-add-unmatched',
    type=bool,
    default=False,
    help='Add new policies for user-agents without policy matches.',
)

flags.add_argument(
    '--uapproxy-add-ua',
    type=bool,
    default=True,
    help='Adds a user-agent object at auto added polices.',
)

flags.add_argument(
    '--uapproxy-add-os',
    type=bool,
    default=True,
    help='Adds a operating system object at auto added polices.',
)

flags.add_argument(
    '--uapproxy-add-device',
    type=bool,
    default=False,
    help='Adds a device object at auto added polices.',
)

flags.add_argument(
    '--uapproxy-add-prefix',
    type=bool,
    default=False,
    help='Adds a prefix object at auto added polices.',
)

flags.add_argument(
    '--uapproxy-permit-unmatched',
    type=bool,
    default=True,
    help='Permit unmatched user-agents.',
)


class CheckResult():
    def __init__(self, permit, policy=None):
        self.permit = permit
        self.policy = policy

    def raise_rejected(self):
        print(self.permit)
        if not self.permit:
            raise HttpRequestRejected(
                status_code=403,
                reason=b'Rejected by user-agent policy.',
                headers={b'Location':b'http://127.0.0.1:8123'},
                body=b'foo',
            )

class UapproxyPlugin(HttpProxyBasePlugin):
    """Permit and deny traffic depending on user-agent policy.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def check_user_agent(self, uap, client_ip):
        # look for matching policies
        for policy in models.Policy.objects.all():
            if policy.policy_check(uap, client_ip):
                models.Policy.objects.filter(uuid=policy.uuid).update(
                    matches=(F("matches") + 1) % 2147483647)
                return CheckResult(permit=policy.permit, policy=policy.priority)

        if self.flags.uapproxy_add_unmatched:
            # add new policy and auxillary objects if no policy has been found
            ua, created = models.UserAgent.objects.get_or_create(
                family=uap['user_agent']['family'],
                major=uap['user_agent']['major'],
                minor=uap['user_agent']['minor'],
                patch=uap['user_agent']['patch'],
            )

            os, created = models.OperatingSystem.objects.get_or_create(
                family=uap['os']['family'],
                major=uap['os']['major'],
                minor=uap['os']['minor'],
                patch=uap['os']['patch'],
                patch_minor=uap['os']['patch_minor'],
            )

            device, created = models.Device.objects.get_or_create(
                family=uap['device']['family'],
                brand=uap['device']['brand'] or '',
                model=uap['device']['model'] or '',
            )

            policy, created = models.Policy.objects.get_or_create(
                permit=self.flags.uapproxy_permit_unmatched,
                ua=ua,
                ua_comparator=models.Policy.COMP_EQ,
                os=os,
                os_comparator=models.Policy.COMP_EQ,
                device=device,
                matches=1,
            )

            return CheckResult(permit=policy.permit, policy=policy.priority)

        return CheckResult(permit=self.flags.uapproxy_permit_unmatched)

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.headers and b'user-agent' in request.headers:
            ua_hdr = request.headers[b'user-agent'][1]
        else:
            ua_hdr = b''
        ua_cache_key = sha256(ua_hdr).hexdigest()

        # parse user-agent (cached)
        ua = cache.get(ua_cache_key)
        if ua is None:
            ua = user_agent_parser.Parse(ua_hdr.decode('ascii'))
            cache.set(ua_cache_key, ua,
                      timeout=settings.UAPPROXY_UAPARSER_TIMEOUT)

        # check policy (cached)
        ip = ipaddress.ip_address(self.client.addr[0])
        ip_cache_key = "{}@{}".format(ua_cache_key, str(ip))
        policy_result = cache.get(ip_cache_key)
        if policy_result is None:
            policy_result = self.check_user_agent(ua, ip)
            cache.set(ip_cache_key, policy_result,
                      timeout=settings.UAPPROXY_POLICY_TIMEOUT)

        policy_result.raise_rejected()

        return request
