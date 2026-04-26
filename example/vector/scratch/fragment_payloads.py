import sys

def fragment(data, size=64):
    return [data[i:i+size] for i in range(0, len(data), size)]

dll = open("dll_b64.txt").read().strip()
exe = open("exe_b64.txt").read().strip()

print("var _payloads = {")
print("    dll: [")
for f in fragment(dll):
    print(f'        "{f}",')
print("    ],")
print("    exe: [")
for f in fragment(exe):
    print(f'        "{f}",')
print("    ]")
print("};")
