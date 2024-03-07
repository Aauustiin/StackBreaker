import GPTCompiler.asm_generator as asm_generator
import GPTCompiler.chain_pack as chain_pack
import subprocess
from GPTCompiler.Shell_coder import generate_shellcode_chain

call_count = 0

def main(padding, out_rop_path, api_key, target):
    checkcounter = 0
    for _ in range(1):
        eax = asm_generator.assembly_generator("GPTCompiler/eax.s")
        rop_file = generate_shellcode_chain(padding, out_rop_path, "GPTCompiler/eax.s", api_key)
        command = "./" + str(target) + " " + str(rop_file)

        output, error = run_command(command)
        print("Output:", output)
        print("Error:", error if error else "No Error") 
        check = checkoutput(eax,output)
        if check == True:
            checkcounter += 1
    success, failure = calculate_success(checkcounter,call_count)
    return success, failure


def checkoutput(eax,output):
    global call_count
    # Increment the counter each time the function is called
    call_count += 1

    if chr(eax) in output:
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
