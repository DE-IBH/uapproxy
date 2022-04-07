from datetime import datetime
from hashlib import sha256
import ipaddress
from ua_parser import user_agent_parser

from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader

from policer import models


def home(request):
    template = loader.get_template('uapproxy/check.html')
    client_ip =  ipaddress.ip_address(request.META.get('REMOTE_ADDR'))

    if request.headers and 'User-Agent' in request.headers:
        ua_hdr = request.headers['User-Agent']
    else:
        ua_hdr = ''
    ua_cache_key = sha256(ua_hdr.encode('utf8')).hexdigest()

    # parse user-agent (cached)
    uap = cache.get(ua_cache_key)
    if uap is None:
        uap = user_agent_parser.Parse(ua_hdr)
        cache.set(ua_cache_key, uap,
                  timeout=settings.UAPPROXY_UAPARSER_TIMEOUT)

    context = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'permit': None,
        'priority': '-',
        'uap': uap,
        'client_ip': client_ip,
    }

    for policy in models.Policy.objects.all():
        if policy.policy_check(uap, client_ip):
            context['permit'] = policy.permit
            context['priority'] = policy.priority
            break

    return HttpResponse(template.render(context, request))
