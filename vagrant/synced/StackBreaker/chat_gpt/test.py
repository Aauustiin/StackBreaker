import asm_generator
import chain_pack


def main(file_name,asm_gadget):
    eax = asm_generator.assembly_generator(file_name)
    chain = translate_asm_gadget(asm_gadget)
    rop_chain = chain_pack.pack_chain(chain)

    file_path = "chaintopass"
    try:
        with open(file_path, 'wb') as file:  # 'xb' mode for creating and writing in binary
            file.write(rop_chain)
    except FileExistsError:
        print(f"The file '{file_path}' already exists.")

    return file_path
    output = getandcheckout(eax)
    success_rate = calculate_success()


# def translate_asm_gadget(asm_gadget):

def getandcheckout(eax):
    return output 

def calculate_success():
    return success_rate