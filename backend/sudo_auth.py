import subprocess

def verify_sudo_password(password: str) -> tuple[bool, str]:
    """
    Verify if the provided sudo password is valid.
    
    Args:
        password (str): The sudo password to verify
        
    Returns:
        tuple[bool, str]: A tuple containing (success, message)
    """
    try:
        # Create a command that requires sudo
        cmd = ['sudo', '-S', 'true']
        
        # Run the command and provide the password
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send the password to stdin
        stdout, stderr = process.communicate(input=f"{password}\n")
        
        # Check the return code
        if process.returncode == 0:
            return True, "Sudo authentication successful"
        else:
            return False, "Invalid sudo password"
            
    except subprocess.SubprocessError as e:
        return False, f"Sudo authentication error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error during sudo authentication: {str(e)}"
