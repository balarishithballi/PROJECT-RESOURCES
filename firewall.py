#!/usr/bin/env python3
# by: Cody Kochmann (fixed for Python3 on macOS/Linux)

from datetime import datetime
from functools import partial
from ipaddress import ip_address
from itertools import cycle, product, islice
from random import randint, shuffle

"""
    This script creates logs matching the pattern 
    of firewall logs to act as a test script to
    simulate input coming from a firewall.
"""

# set to True to get ipv6 addresses in logs too
INCLUDE_IPV6 = False

# shortcut for getting time
now = datetime.now

# random.choice acceleration stream
def random_choice_stream(collection, min_buffer=4096):
    """ takes a collection of items and yields a
    random selection from it without needing to
    call for randomness on every selection. """
    assert isinstance(collection, list), collection
    # multiply the collection to reduce shuffle ops
    while len(collection) < min_buffer:
        collection = collection * 2
    while shuffle(collection) is None:
        yield from collection

# cycler of connection ids
ids = cycle(range(1, 65536))

# random interface generation
interfaces = [f'eth{i}' for i in range(16)]
random_interfaces = random_choice_stream(interfaces)

# random mac generation
all_hex_pairs = [''.join(i) for i in product('0123456789abcdef', 
repeat=2)]
random_hex_pairs = random_choice_stream(all_hex_pairs)

def rand_mac():
    return ':'.join(islice(random_hex_pairs, 6))

# random ip generation
rand_ip_int = partial(
    randint,
    1,
    2**(128 if INCLUDE_IPV6 else 32) - 1
)

def rand_ip():
    while True:
        try:
            return ip_address(rand_ip_int())
        except:
            continue

# random protocol generation
protocols = ['UDP', 'TCP']
random_protocols = random_choice_stream(protocols)

# template for firewall log output
template = (
    "{ts} IN={dev_in} OUT={dev_out} MAC={mac} SRC={src} DST={dst} "
    "LEN={length} TOS=0x00 PREC=0x00 TTL={ttl} ID={_id} "
    "PROTO={proto} SPT={spt} DPT={dpt} WINDOW={window} "
    "RES=0x00 ACK PSH URGP=0"
).format

# glues everything together
def rand_template():
    return template(
        ts=now().isoformat(),
        dev_in=next(random_interfaces),
        dev_out=next(random_interfaces),
        mac=rand_mac(),
        src=rand_ip(),
        dst=rand_ip(),
        length=randint(1, 65536),
        proto=next(random_protocols),
        spt=randint(1, 65536),
        dpt=randint(1, 65536),
        window=randint(128, 4096),
        ttl=randint(10, 4096),
        _id=next(ids)
    )

if __name__ == '__main__':
    # open firewall.log and keep appending logs
    with open("firewall.log", "a") as logfile:
        while True:
            batch = '\n'.join(rand_template() for _ in range(128))
            logfile.write(batch + "\n")
            logfile.flush()  # ensure data is written immediately

