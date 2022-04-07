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
from datetime import datetime
import django
from django.conf import settings
from django.core.cache import cache
from django.db.models import F
from django.template.loader import render_to_string
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
    action='store_true',
    help='Add new policies for user-agents without policy matches.',
)

flags.add_argument(
    '--uapproxy-add-os',
    action='store_true',
    help='Add a operating system object at auto added policies.',
)

flags.add_argument(
    '--uapproxy-add-device',
    action='store_true',
    help='Add a device object at auto added policies.',
)

flags.add_argument(
    '--uapproxy-add-prefix',
    action='store_true',
    help='Add a prefix object at auto added policies.',
)

flags.add_argument(
    '--uapproxy-add-pfx-ipv4-len',
    type=int,
    default=24,
    help="Used prefix length on client's ipv4 addresses when adding prefix objects at auto added policies.",
)

flags.add_argument(
    '--uapproxy-add-pfx-ipv6-len',
    type=int,
    default=64,
    help="Used prefix length on client's ipv6 addresses when adding prefix objects at auto added policies.",
)

flags.add_argument(
    '--uapproxy-permit-unmatched',
    action='store_true',
    help='Permit clients without any policy match.',
)


class CheckResult():
    def __init__(self, permit, priority, uap, client_ip):
        self.permit = permit

        if not permit:
            self.context = {
                'timestamp': datetime.now().isoformat(timespec='seconds'),
                'permit': False,
                'priority': priority,
                'uap': uap,
                'client_ip': client_ip,
            }

    def raise_rejected(self):
        if not self.permit:
            body = render_to_string("uapproxy/check.html", self.context)

            raise HttpRequestRejected(
                status_code=403,
                reason=b'User-agent access denied.',
                headers={b'Content-Type':b'text/html; charset=utf-8'},
                body=body.encode('utf8'),
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
                return CheckResult(policy.permit, policy.priority, uap, client_ip)

        if self.flags.uapproxy_add_unmatched:
            # add new policy and auxillary objects if no policy has been found
            ua, created = models.UserAgent.objects.get_or_create(
                family=uap['user_agent']['family'],
                major=uap['user_agent']['major'],
                minor=uap['user_agent']['minor'],
                patch=uap['user_agent']['patch'],
            )

            if self.flags.uapproxy_add_os:
                os, created = models.OperatingSystem.objects.get_or_create(
                    family=uap['os']['family'],
                    major=uap['os']['major'],
                    minor=uap['os']['minor'],
                    patch=uap['os']['patch'],
                    patch_minor=uap['os']['patch_minor'],
                )
            else:
                os = None

            if self.flags.uapproxy_add_device:
                device, created = models.Device.objects.get_or_create(
                    family=uap['device']['family'],
                    brand=uap['device']['brand'] or '',
                    model=uap['device']['model'] or '',
                )
            else:
                device = None

            if self.flags.uapproxy_add_prefix:
                if client_ip.version == 4:
                    nw = ipaddress.ip_interface("{}/{}".format(client_ip, self.flags.uapproxy_add_pfx_ipv4_len))
                else:
                    nw = ipaddress.ip_interface("{}/{}".format(client_ip, self.flags.uapproxy_add_pfx_ipv6_len))

                prefix, created = models.Prefix.objects.get_or_create(
                    prefix=str(nw.network.network_address),
                    length=nw.network.prefixlen,
                )
            else:
                prefix = None

            policy, created = models.Policy.objects.get_or_create(
                permit=self.flags.uapproxy_permit_unmatched,
                ua=ua,
                ua_comparator=models.Policy.COMP_EQ,
                os=os,
                os_comparator=models.Policy.COMP_EQ,
                device=device,
                prefix=prefix,
                matches=1,
            )

            return CheckResult(policy.permit, policy.priority, uap, client_ip)

        return CheckResult(self.flags.uapproxy_permit_unmatched, None, uap, client_ip)

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
