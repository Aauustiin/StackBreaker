import struct

def pack_chain(gpt_gadgets):
    # gpt_gadgets = ["0X0806e13b", "0x000000", "0xzzzzz", "0XX0806e13b", "0x080a8cb6", "0x08056bd5", "0x0806e13b", "0x08056190", "0x0806e13b", "0x08056190", "0x080481c9", "0x080da060", "0x0806e162", "0x080da060", "0x0806e13b"]
    rop_chain = form_chain(gpt_gadgets)
    # Convert and pack the ROP chain
    p = b''  # Initialize an empty bytes object
    for gadget in rop_chain:
        p += pack_gadget(gadget)

    print(p)  # Print the packed ROP chain

def form_chain(gpt_gadgets):
    chain = []
    for gadget in gpt_gadgets:
        if gadget.startswith("0x"):
            new_gadget = gadget[2:]  # Remove the '0x' prefix
        else:
            print(f"Error: gadget {gadget} does not start with '0x'")
            continue  

        try:
            int(new_gadget, 16)
            chain.append(gadget)
        except ValueError:
            print(f"Error: gadget {gadget} is not a hexadecimal number")

    return chain
    
def pack_gadget(gadget):
    gadget_int = int(gadget, 16)
    print(gadget_int)
    return struct.pack('<I', gadget_int) 
