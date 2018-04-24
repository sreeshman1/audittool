import base64
from datetime import datetime
import hashlib
import hmac
import json
import base64
import hashlib
import hmac
import random
import socket
import time
import requests
import re

def create_signature(secret_key, method, md5, ctype, date, uri):
    # Get the string to sign
    string_sign = string_to_sign(method, md5, ctype, date, uri)

    # Compute the authorization header
    hmac_sha1 = hmac.new(secret_key.encode(), string_sign.encode(), hashlib.sha1).digest()
    computed_sig = base64.b64encode(hmac_sha1)
    return computed_sig

def string_to_sign(method, md5, ctype, date, uri):
    "Returns the string to sign"
    parts = []

    # Add the components
    parts.append(method.upper())
    parts.append(str(md5))
    parts.append(str(ctype))
    if date:
        parts.append(str(date))
    parts.append(str(uri))

    return str("\n".join(parts))

ISO_DATE_RE = re.compile(
    "(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\.?(?P<microsec>\d{6})?")

def isodate_to_datetime(s, match=None):
    "Converts an ISO 8601 string to a datetime object"
    if match is None:
        match = ISO_DATE_RE.match(s)
    if match:
        year, month, day, hour, minute, second, sub = map(
            lambda x: int(x) if x else 0, match.groups())
        print(sub)
        return datetime(year, month, day, hour, minute, second, sub)
    return None

def trace_request(data, url):
    d = json.loads(data)
    date = isodate_to_datetime(d["date"])
    datestring = date.strftime("%Y-%m-%d %H:%M:%S.%f")
    print(datestring)
    md5 = base64.b64encode(hashlib.md5(data.encode()).digest())
    endpoint = "http://api.kiip.me/2.0/{}/?r={}"
    curlurl = endpoint.format(url,time.time)
    jaegertoken = "trace-{}".format("f6f07e39617364e0")
    signature = create_signature("3b46e5f42299f1697193bb843ed8dbf4", "Post", md5, "application/json", datestring, curlurl)
    headers = {
        'Date' : datestring,
        'Content-Type' : 'application/json',
	    'jaeger-debug-id': jaegertoken,
	    'Content-MD5' : md5,
	    'Authorization' : "KiipV2 %s:%s".format("3b46e5f42299f1697193bb843ed8dbf4", signature)
    }
    r = requests.post(curlurl,data=data,headers=headers)
    r.json()
    return json.loads(r.content),jaegertoken
