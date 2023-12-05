import asm_generator
import chain_pack
import subprocess

call_count = 0


def main(file_name,asm_gadget):
    eax = asm_generator.assembly_generator(file_name)
    chain = translate_asm_gadget(asm_gadget)
    rop_chain = chain_pack.pack_chain(chain)

    file_path = "rop_chain"
    try:
        with open(file_path, 'wb') as file:  # 'xb' mode for creating and writing in binary
            file.write(rop_chain)
    except FileExistsError:
        print(f"The file '{file_path}' already exists.")

    output, error = run_command('./vuln3-32 rop_chain')  # Replace 'ls' with your command
    print("Output:", output)
    print("Error:", error if error else "No Error") 
    check = checkoutput(eax,output)
    if check == True:
        checkcounter += 1
    success, failure = calculate_success(checkcounter,call_count)

    return file_path

# def translate_asm_gadget(asm_gadget):

def checkoutput(eax,output):
    global call_count
    # Increment the counter each time the function is called
    call_count += 1

    if eax == output:
        check = True
        return check
    else:
        check = False

    return check

def calculate_success(success_outcomes,total_outcomes):

    failure = total_outcomes - success_outcomes
    success_rate = (success_outcomes/total_outcomes)*100
    failure_rate = (failure/total_outcomes)*100
    print("Success rate: ",success_rate,"%")
    print("Failure rate: ",failure_rate,"%")
    
    return success_rate,failure_rate


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr
