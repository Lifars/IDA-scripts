# Author: Ladislav Baco, LIFARS
# Date: July 22, 2020
#
# (c) 2020 LIFARS
# This code is licensed under MIT license (see LICENSE for details)


import idaapi
import idautils
import ida_name
import ida_bytes

from base64 import b64decode
from itertools import cycle, izip

def get_params(ea):
    data_addr = None
    length = None
    inst = idautils.DecodePreviousInstruction(ea)
    if (inst != None) and (inst.get_canon_mnem() == "mov"):
        length = inst.Op2.value
        inst2 = idautils.DecodePreviousInstruction(inst.ea)
        if (inst2 != None) and (inst2.get_canon_mnem() == "mov"):
            inst3 = idautils.DecodePreviousInstruction(inst2.ea)
            if (inst3 != None) and (inst3.get_canon_mnem() == "lea"):
                length = inst.Op2.value
                data_addr = inst3.Op2.addr      

    return data_addr, length

def decrypt_string(data, key):
    crypt = b64decode(data)
    plain = "".join(chr(ord(c)^ord(k)) for c,k in izip(crypt, cycle(key)))
    return b64decode(plain)

arch = 64 if idaapi.get_inf_structure().is_64bit() else 32
ea = ida_name.get_name_ea(idaapi.BADADDR, "main.decodeString")
key_addr = ida_name.get_name_ea(idaapi.BADADDR, "main.encoderKey")
key = ida_bytes.get_bytes(ida_bytes.get_dword(key_addr), ida_bytes.get_dword(key_addr + arch/8))

for xref in idautils.CodeRefsTo(ea, True):
    inst = idautils.DecodeInstruction(xref)
    if (inst != None) and (inst.get_canon_mnem() == "call"):
        data_addr, length = get_params(xref)
        data = ida_bytes.get_bytes(data_addr, length)
        decrypted_str = decrypt_string(data, key)
        print "0x{:08x} -> 0x{:x}[0x{:x}] = \"{}\"".format(xref, data_addr, length, decrypted_str)
        ida_bytes.set_cmt(xref, decrypted_str, False)