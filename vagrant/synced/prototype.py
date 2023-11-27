import re

def parse_out_rop(path, out_rop):
    rop_gadgets = {
        ": mov dword ptr [edx], eax ; ret": None,
        ": pop edx ; ret:": None,
        ": pop eax ; ret:": None
    }

    data_addrPat = r'^.*pack\(\'<I\', (0x(?:[0-9A-Fa-f]){8}\) # @ .data\n'
    data_addrPat = re.compile(data_addrPat, re.MULTILINE)
    data_addr = data_addrPat.search(out_rop).string

    for gaget in rop_gadgets.keys():
        gagetPat = r'^(0x[0-9A-Fa-f]{8})\s*'+ gaget
        gagetPat = re.compile(gagetPat, re.MULTILINE)

        gagetAdds = gagetPat.findall(out_rop)
        rop_gadgets[gaget] = gagetAdds
