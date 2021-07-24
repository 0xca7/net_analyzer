"""
    does filtering of network data
    for example, remove IPv6 ips
"""

import re
from napy.global_defs import *

RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

"""
remove all IPv6 addresses from a dump
"""
def filter_remove_ipv6(data):
    return list(filter(
        lambda x: re.match(RE_IPV4, x[FIELD_INDEX_SIP]), data)
    )
