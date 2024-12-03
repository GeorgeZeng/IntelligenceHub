# Gets the raw API responses and saves them to raw_responses
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
from dotenv import load_dotenv
from src.new_api_utils.ip_utils_combined import check_ip_abuseipdb, check_ip_cloudmersive, check_ip_criminalip, check_ip_virustotal
from src.new_api_utils.domain_utils_combined import check_domain_cloudmersive, check_domain_virustotal
from src.new_api_utils.virus_utils_combined import check_virus_virustotal, check_virus_cloudmersive

# Load environment variables
load_dotenv()

# IP was on 11 blacklists (6OCT24)
ip_address = "109.120.176.11"

# keitaro malware domain
domain = "statsrvv.com"

# Use this script file as the sample file
sample_file_path = __file__

# Ryuk md5 hash
sample_file_hash = "c0202cf6aeab8437c638533d14563d35"

# Create a 'raw_responses' directory if it doesn't exist
raw_responses_dir = os.path.join(os.path.dirname(__file__), 'raw_responses')
os.makedirs(raw_responses_dir, exist_ok=True)

# Function to save JSON response
def save_json_response(data, filename):
    file_path = os.path.join(raw_responses_dir, filename)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Saved response to {file_path}")

# IP checks
try:
    abuseipdb_response = check_ip_abuseipdb(ip_address)
    save_json_response(abuseipdb_response, "ip_abuseipdb_response.json")

    cloudmersive_ip_response = check_ip_cloudmersive(ip_address)
    save_json_response(cloudmersive_ip_response, "ip_cloudmersive_response.json")

    criminalip_response = check_ip_criminalip(ip_address)
    save_json_response(criminalip_response, "ip_criminalip_response.json")

    virustotal_ip_response = check_ip_virustotal(ip_address)
    save_json_response(virustotal_ip_response, "ip_virustotal_response.json")

    # Domain checks
    cloudmersive_domain_response = check_domain_cloudmersive(domain)
    save_json_response(cloudmersive_domain_response, "domain_cloudmersive_response.json")

    virustotal_domain_response = check_domain_virustotal(domain)
    save_json_response(virustotal_domain_response, "domain_virustotal_response.json")

    # Virus checks
    cloudmersive_virus_response = check_virus_cloudmersive(sample_file_path)
    save_json_response(cloudmersive_virus_response, "virus_cloudmersive_response.json")

    virustotal_hash_response = check_virus_virustotal(sample_file_hash)
    save_json_response(virustotal_hash_response, "virus_virustotal_response.json")

    print("All API responses have been saved to JSON files in the 'raw_responses' directory.")
except Exception as e:
    print(f"An error occurred: {str(e)}")
