#!/usr/bin/env python3

from bcc import BPF
import time, sys

device = "lo"
b = BPF(src_file=sys.argv[1], cflags=["-DDEST_PORT=7999"])
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)
#fn = b.load_func("filter", BPF.SOCKET_FILTER)
#BPF.attach_raw_socket(fn, interface)


try:
  b.trace_print()
except KeyboardInterrupt:
  pass

b.remove_xdp(device, 0)
