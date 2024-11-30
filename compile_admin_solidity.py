import solcx
from solcx import compile_files

# Install solc version 0.8.0 if not already installed
try:
    solcx.install_solc('0.8.0')
except solcx.exceptions.SolcInstallationError as e:
    print(f"Error installing solc: {e}")
    exit()

def compile_solidity_file(file_path):
    # Compile Solidity code using solcx
    compiled_output = compile_files([file_path], output_values=["bin", "abi"], optimize=True, solc_version='0.8.0')

    # Check for errors
    if "errors" in compiled_output:
        print("Error compiling Solidity file:")
        print(compiled_output["errors"])
        return None

    # Return compiled bytecode and ABI
    return compiled_output

# Compile AdminLogger.sol
compiled_output = compile_solidity_file('solidity/AdminLogger.sol')  # Update file path if necessary
if compiled_output:
    print("Compiled bytecode and ABI:")
    print(compiled_output)
