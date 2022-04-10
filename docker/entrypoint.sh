#!/bin/sh

MODE="$1"
shift

case "$MODE" in
    django)
        python3 ./manage.py migrate --no-input --force-color
        exec gunicorn -b 0.0.0.0 $@ uapproxy.wsgi
        exit 2
        ;;
    static)
        cd static
        exec python3 -m http.server
        exit 2
        ;;
    proxy)
        python3 ./manage.py migrate --no-input --force-color
        exec /usr/local/bin/proxy --hostname 0.0.0.0 --plugins uapproxy.proxy.UapproxyPlugin $@
        exit 2
        ;;
    '')
        echo << EOH
You need to specify the run mode as command. Valid run modes:

    django: runs the Django admin panel (tcp/8080)
    static: provides assets for the Django admin panel (tcp/8000)
    proxy : runs the proxy.py instance with uapproxy plugin (tcp/8899)

EOH
        exit 1
        ;;
    *)
        echo "Oops, mode '$MODE' is not known!" 1>&2
        exit 1
        ;;
esac
