#!/usr/bin/env python3
# solve_rev.py — extract flag from the compiled binary by searching sentinel and XORing
import sys

if len(sys.argv) != 2:
    print("Usage: python3 solve_rev.py <binary>")
    sys.exit(1)

fn = sys.argv[1]
data = open(fn, "rb").read()

sent = bytes([0xFE,0xED,0xFA,0xCE])
i = data.find(sent)
if i == -1:
    print("Sentinel not found")
    sys.exit(1)

# assume rest of blob until a 0x00 or until a reasonable length (max 128)
start = i + len(sent)
# we don't know exact length; try read until a non-printable after xor or max 128
blob = data[start:start+128]  # read up to 128 bytes of encrypted data

# try all possible single-byte XOR keys and show printable candidates
import string
def is_printable(s):
    return all(32 <= c < 127 for c in s)

candidates = []
for k in range(1,256):
    dec = bytes([b ^ k for b in blob])
    # find terminating null (if present) to clip
    if 0 in dec:
        dec = dec[:dec.index(0)]
    if len(dec) >= 8 and all(chr(c) in string.printable for c in dec):
        s = dec.decode('ascii', errors='ignore')
        if s.startswith("paavaiCTF{") and "}" in s:
            print("FOUND FLAG with key 0x{:02x}: {}".format(k, s))
            sys.exit(0)
        # also collect printable candidates for manual inspection
        candidates.append((k, s[:80]))

print("No direct flag found automatically. Printable candidates (key, snippet):")
for k,s in candidates[:30]:
    print(hex(k), s)
print("\\nIf you ran the generator, the instructor knows the exact XOR key used.")
