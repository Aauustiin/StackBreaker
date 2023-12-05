from openai import OpenAI
from GadgetTrimmer import *
from io import StringIO


def compile_asm(assembly: str, gadgets: str):

    trimmed_gadgets = standard_trim(gadgets)

    assembly_so_far = StringIO()
    for line in assembly.splitlines():
        assembly_so_far.write(line + '\n')
        client = OpenAI(api_key=API_KEY)

        # DESCRIBE THE SIDE EFFECTS THAT MUST BE AVOIDED

        completion = client.chat.completions.create(
            model="gpt-3.5-turbo-1106",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant"},
                {"role": "user",
                 "content": "The following assembly program is being compiled into ROP gadgets:\n\n" + assembly_so_far.getvalue() + "\n\nWhen compiling the line:\n\n" + line + "\n\nWhat side effects must be avoided in order to maintain program correctness in this specific case?"}
            ],
            temperature=0
        )

        response = completion.choices[0].message.content
        print(response)

        # GENERATE SOLUTION FROM ROP GADGETS

        clean_line = line.replace(',', '')
        tokens = clean_line.split()
        keyword_gadgets = keyword_trim(trimmed_gadgets, tokens)

        prompt = "Use the provided gadgets to create a ROP chain that executes the following line of assembly\n\n" + line + "\n\n" + response + "\n\nAccomplish this task by following these steps:\n\n1. Identify 5 different gadgets that could be used to accomplish the task.\n\n2. Come up with 3 different potential solutions.\n\n3. Evaluate the correctness and simplicity of your solutions and decide upon the best one" + "\n\nGadgets:\n\n" + keyword_gadgets + "\n\n"

        completion = client.chat.completions.create(
            model="gpt-4-1106-preview",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant"},
                {"role": "user", "content": prompt}
            ],
            temperature=0
        )

        response = completion.choices[0].message.content
        print(response)

        # FORMAT ANSWER CORRECTLY

        completion = client.chat.completions.create(
            model="gpt-3.5-turbo-1106",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant"},
                {"role": "user", "content": "The following is a description of a ROP chain:\n\n" + response + "\n\nExtract the rop chain from this description and write it out between two curly braces, with each gadget separated by a newline. For example:\n\n{\nGadget\nGadget\nGadget\n}"}
            ],
            temperature=0
        )

        response = completion.choices[0].message.content
        print(response)

        # REMOVE DUMMY VALUES

        completion = client.chat.completions.create(
            model="gpt-3.5-turbo-1106",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant"},
                {"role": "user",
                 "content": "Fill in any missing values in:\n\n" + response + "\n\nWith arbitrarily chosen values. If there are no missing values, then repeat the input."}
            ],
            temperature=0
        )

        response = completion.choices[0].message.content
        print(response)

        copy = False
        buffer = StringIO()
        for response_line in response.splitlines():
            if "{" in response_line:
                copy = True
            elif "}" in response_line:
                copy = False
            elif copy:
                buffer.write(response_line + '\n')

        with open("response.txt", 'a') as out_file:
            out_file.write(buffer.getvalue())

    print("Finished")


if __name__ == "__main__":
    with open("../out-rop.txt", "r") as in_file:
        in_gadgets = in_file.read()
    compile_asm("mov eax, 11\nmov ebx, 0\nint 0x80", in_gadgets)
