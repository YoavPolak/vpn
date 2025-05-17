import ipaddress  # Import the ipaddress module to work with IP addresses

def is_valid_ip(address: str) -> bool:
    """
    Checks if the provided address is a valid IP address (either IPv4 or IPv6).
    
    Args:
    - address (str): The IP address string to be validated.

    Returns:
    - bool: True if the address is a valid IP, False otherwise.
    """
    try:
        # Attempt to create an IP address object from the provided address
        ipaddress.ip_address(address)  # This works for both IPv4 and IPv6 addresses
        return True  # If no exception occurs, the address is valid
    except ValueError:
        # If a ValueError is raised, the address is not a valid IP
        return False  # Return False for invalid IP addresses
