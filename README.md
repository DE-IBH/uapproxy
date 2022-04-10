uapproxy - user-agent policy proxy
==================================

Uapproxy is a proxy to policy access depending on the user-agent string. It uses the [ua-parser](https://pypi.org/project/ua-parser/) python package to decode the `User-Agent` http header string.

Uaproxy can be used to prevent outdated or unwanted browsers from accessing the internet if proxy usage is enforced.


Deployment
----------

Uapproxy is provided as docker image on [quay.io](https://quay.io/repository/ibh/uapproxy?tab=tags). The container image's entry point accepts three different modes provided as the first command parameter:

**django**
    Runs the Django admin webinterface (`tcp/8000`).

**proxy**
    Runs *proxy.py* with the uapproxy plugin (`tcp/8899`). Additional *proxy.py* parameters can be provided via the command list.

**static**
    Runs a simple http server providing the Django admin's static asset files (`tcp/8000`).


Configuration
-------------

Depending on the start mode the following configuration options can be passed.

Django
______

The Django application is configured by the following environment variables. You need to set at least the [`SECRET_KEY`](https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-SECRET_KEY). Uapproxy has some caching timeout settings:

**UAPPROXY_UAPARSER_TIMEOUT**
    The caching timeout in secondes for `User-Agent` string parsing (default: `86400`).

**UAPPROXY_POLICY_TIMEOUT**
    The caching timeout in seconds for policy check results (default: `30`).


 The following Django settings are provided:

```python
# TODO: You must set a secure secret!
# https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-SECRET_KEY
SECRET_KEY=

# https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-DEBUG
DEBUG=False

# https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-ALLOWED_HOSTS
ALLOWED_HOSTS=[]

# https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-LANGUAGE_CODE
LANGUAGE_CODE='en-us'

# https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-TIME_ZONE
TIME_ZONE='UTC'
```

Proxy
_____


You can provide *proxy.py* settings as additional command parameters. The following uapproxy specific settings are available:

**--uapproxy-add-unmatched**
    Add new policies for user-agents without policy matches.

**--uapproxy-add-os**
    Add a operating system object at auto added policies.

**--uapproxy-add-device**
    Add a device object at auto added policies.

**--uapproxy-add-prefix**
    Add a prefix object at auto added policies.

**--uapproxy-add-pfx-ipv4-len UAPPROXY_ADD_PFX_IPV4_LEN**
    Used prefix length on client's ipv4 addresses when adding prefix objects at auto added policies.

**--uapproxy-add-pfx-ipv6-len UAPPROXY_ADD_PFX_IPV6_LEN**
    Used prefix length on client's ipv6 addresses when adding prefix objects at auto added policies.

**--uapproxy-permit-unmatched**
    Permit clients without any policy match.
