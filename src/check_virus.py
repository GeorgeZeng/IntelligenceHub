import os
import hashlib

from src.new_api_utils.virus_utils_combined import check_virus_virustotal, check_virus_cloudmersive
from src.new_api_utils.parser_combined import parser_virus_virustotal, parser_virus_cloudmersive
from src.response_parser import merge_results, format_display_result, add_source_to_each_data_point

def check_virus(input_data):
    """
    Check virus information for either a file hash or filepath.
    For hashes: only calls VirusTotal
    For files: calls both VirusTotal and Cloudmersive
    Args:
        input_data (str): Either a file hash or a filepath
    """
    result = {}
    enter_email = False
    message = ""
    external_links = {}
    
    # Determine if input is a file path or hash
    is_file = os.path.exists(input_data)
    
    if is_file:
        # Handle file path - call both services
        file_path = input_data
        file_hash = sha256_file(file_path)
        message = f"Result of {os.path.basename(file_path)}"
        
        # Cloudmersive scan
        cloudmersive_data = check_virus_cloudmersive(file_path)
        result = merge_results(result, add_source_to_each_data_point(parser_virus_cloudmersive(cloudmersive_data), 'Cloudmersive'))
        
        # Add Cloudmersive link
        link_for_cloudmersive = {'Cloudmersive': "https://api.cloudmersive.com/docs/virus.asp"}
        external_links = {**external_links, **link_for_cloudmersive}
        
        # VirusTotal scan with generated hash
        virustotal_data = check_virus_virustotal(file_hash)
        if not virustotal_data.get('error'):
            enter_email = True
            result = merge_results(result, add_source_to_each_data_point(parser_virus_virustotal(virustotal_data), 'VirusTotal'))
            link_for_virustotal = {'VirusTotal': f"https://www.virustotal.com/gui/file/{file_hash}"}
            external_links = {**external_links, **link_for_virustotal}
    else:
        # Handle hash input - only call VirusTotal
        message = f"Result of {input_data}"
        virustotal_data = check_virus_virustotal(input_data)
        if not virustotal_data.get('error'):
            enter_email = True
            result = merge_results(result, add_source_to_each_data_point(parser_virus_virustotal(virustotal_data), 'VirusTotal'))
            link_for_virustotal = {'VirusTotal': f"https://www.virustotal.com/gui/file/{input_data}"}
            external_links = {**external_links, **link_for_virustotal}
    
    # Format result for display in HTML
    result = format_display_result(result)
    
    return result, enter_email, message, external_links

def sha256_file(file_path):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Open the file in binary mode
    with open(file_path, "rb") as f:
        # Read the file in chunks to avoid using too much memory
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    # Return the hexadecimal digest of the hash
    return sha256_hash.hexdigest()