#!/usr/bin/env python3
"""Pure adapters for fresh frozen support config; no host actions or CLI.

Callers must verify the CURRENT frozen source, runtime image/schema and target
credentials before using these results in a private copy. These functions do
not restore a database, write a file, start a service or enable staged flags.
Do not use a staged Kuma/Tracearr database to recover cleared source settings.
"""
import copy
import urllib.parse

SOURCE = '192.168.0.29'
NAS = '192.168.0.220'
PORTS = {32400: 32400, 8989: 8989, 7878: 7878, 7879: 7879, 9696: 9696,
         1337: 1337, 5055: 5055, 8080: 8082, 8081: 8081, 8082: 8082,
         3002: 3002, 3001: 3001, 7330: 7330, 61208: 61208,
         8765: 8765, 8877: 8877, 5690: 5690, 8085: 8085, 13378: 13378,
         5000: 5000, 8484: 8484, 8084: 8084, 8086: 8086}


def endpoint(value):
    """Retarget reviewed source LAN endpoints; public and unknown URLs stay."""
    if not isinstance(value, str) or not value.startswith(('http://', 'https://')):
        return value
    parsed = urllib.parse.urlsplit(value)
    if parsed.hostname != SOURCE or parsed.port not in PORTS:
        return value
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('Embedded endpoint credentials require a dedicated adapter.')
    return parsed._replace(netloc=NAS + ':' + str(PORTS[parsed.port])).geturl()


def validate_tree(value):
    active = set()
    count = 0
    def visit(item, depth):
        nonlocal count
        count += 1
        if count > 10000 or depth > 24:
            raise ValueError('Support configuration exceeds its structure bound.')
        if isinstance(item, (dict, list)):
            if id(item) in active:
                raise ValueError('Recursive support configuration is unsupported.')
            active.add(id(item))
            if isinstance(item, dict) and any(not isinstance(key, str) for key in item):
                raise ValueError('Support configuration has a non-text key.')
            for child in item.values() if isinstance(item, dict) else item:
                visit(child, depth + 1)
            active.remove(id(item))
        elif item is not None and not isinstance(item, (str, bool, int, float)):
            raise ValueError('Support configuration has an unsupported value.')
    visit(value, 0)


def connections(value):
    validate_tree(value)
    def adapt(item):
        if isinstance(item, dict):
            return {key: adapt(child) for key, child in item.items()}
        if isinstance(item, list):
            return [adapt(child) for child in item]
        return endpoint(item)
    return adapt(value)


def kometa(document, api_keys):
    """Preserve source policy; adapt Plex and HD/4K/TV connections and keys.

    Pass keys read from the IMPORTED NAS Arr configs, not from an old source or
    staged NAS export. Caller must check environment overrides separately.
    Optional Tautulli settings are preserved for explicit dependency review.
    """
    if not isinstance(document, dict):
        raise ValueError('Kometa configuration must be a mapping.')
    validate_tree(document)
    result = copy.deepcopy(document)
    names = {'sonarr': 'sonarr', 'sonarr-nas': 'sonarr',
             'radarr': 'radarr', 'radarr-nas': 'radarr',
             'radarr4k': 'radarr4k', 'radarr4k-nas': 'radarr4k',
             'plex': 'plex', 'plex-nas': 'plex'}

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key in ('plex', 'radarr', 'sonarr') and isinstance(child, dict) and 'url' in child:
                    url = urllib.parse.urlsplit(child['url'])
                    if url.scheme not in ('http', 'https'):
                        raise ValueError('A Kometa connection URL needs runtime review.')
                    application = names.get(url.hostname)
                    if url.hostname in (SOURCE, NAS):
                        application = {32400: 'plex', 8989: 'sonarr', 7878: 'radarr', 7879: 'radarr4k'}.get(url.port)
                        if application is None:
                            raise ValueError('A Kometa LAN connection has an unreviewed port.')
                    if application is None:
                        # Public/custom endpoints are not silently moved.
                        visit(child)
                        continue
                    if ((key == 'radarr' and application not in ('radarr', 'radarr4k'))
                            or (key != 'radarr' and application != key)):
                        raise ValueError('A Kometa connection points to the wrong application.')
                    if url.username is not None or url.password is not None:
                        raise ValueError('Embedded Kometa credentials require review.')
                    port = {'plex': 32400, 'sonarr': 8989, 'radarr': 7878, 'radarr4k': 7879}[application]
                    child['url'] = url._replace(netloc=NAS + ':' + str(port)).geturl()
                    if application != 'plex':
                        if 'token' in child:
                            credential = 'token'
                        elif 'api_key' in child:
                            credential = 'api_key'
                        else:
                            # Kometa supports partial per-library overrides.
                            # A 4K URL override must receive the 4K NAS token,
                            # rather than inheriting a different global key.
                            credential = 'token'
                        secret = api_keys.get(application)
                        if not isinstance(secret, str) or not secret or any(c.isspace() for c in secret):
                            raise ValueError('An imported NAS Arr key is unavailable.')
                        child[credential] = secret
                visit(child)
    visit(result)
    return result


def kuma_monitor(row):
    """Adapt one SOURCE monitor; preserve active flags and notification state."""
    result = copy.deepcopy(row)
    if 'url' in result:
        result['url'] = endpoint(result['url'])
    if result.get('hostname') == SOURCE and result.get('port') in PORTS:
        result['hostname'] = NAS
        result['port'] = PORTS[result['port']]
    # Notification tables, joins, secrets, pauses and Docker host IDs need the
    # caller's source-authoritative database restore; never invent these here.
    return result
