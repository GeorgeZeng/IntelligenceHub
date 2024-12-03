import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
from src.new_api_utils.parser_combined import (
    parser_abuseipdb, 
    parser_criminalip, 
    parser_ip_cloudmersive, 
    parser_ip_virustotal, 
    parser_domain_cloudmersive, 
    parser_domain_virustotal, 
    parser_virus_cloudmersive, 
    parser_virus_virustotal 
)

parsed_responses_dir = os.path.join(os.path.dirname(__file__), 'parsed_responses')
os.makedirs(parsed_responses_dir, exist_ok=True)

def read_raw_response(filename):
    file_path = os.path.join(os.path.dirname(__file__), 'raw_responses', filename)
    with open(file_path, 'r') as f:
        return json.load(f)

def save_json_response(data, filename):
    file_path = os.path.join(parsed_responses_dir, filename)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Saved parsed response to {file_path}")

try:
    # IP checks
    virustotal_ip_response = read_raw_response('ip_virustotal_response.json')
    parsed_virustotal_ip = parser_ip_virustotal(virustotal_ip_response)
    save_json_response(parsed_virustotal_ip, "ip_virustotal_parsed.json")

    cloudmersive_ip_response = read_raw_response('ip_cloudmersive_response.json')
    parsed_cloudmersive_ip = parser_ip_cloudmersive(cloudmersive_ip_response)
    save_json_response(parsed_cloudmersive_ip, "ip_cloudmersive_parsed.json")

    # Add AbuseIPDB processing
    abuseipdb_response = read_raw_response('ip_abuseipdb_response.json')
    parsed_abuseipdb = parser_abuseipdb(abuseipdb_response)
    save_json_response(parsed_abuseipdb, "ip_abuseipdb_parsed.json")

    # criminalip_response = read_raw_response('ip_criminalip_response.json')
    # parsed_criminalip = parser_criminalip(criminalip_response)
    # save_json_response(parsed_criminalip, "ip_criminalip_parsed.json")

    # Domain checks
    cloudmersive_domain_response = read_raw_response('domain_cloudmersive_response.json')
    parsed_cloudmersive_domain = parser_domain_cloudmersive(cloudmersive_domain_response)
    save_json_response(parsed_cloudmersive_domain, "domain_cloudmersive_parsed.json")

    virustotal_domain_response = read_raw_response('domain_virustotal_response.json')
    parsed_virustotal_domain = parser_domain_virustotal(virustotal_domain_response)
    save_json_response(parsed_virustotal_domain, "domain_virustotal_parsed.json")

    # Virus checks
    cloudmersive_virus_response = read_raw_response('virus_cloudmersive_response.json')
    parsed_cloudmersive_virus = parser_virus_cloudmersive(cloudmersive_virus_response)
    save_json_response(parsed_cloudmersive_virus, "virus_cloudmersive_parsed.json")

    virustotal_virus_response = read_raw_response('virus_virustotal_response.json')
    parsed_virustotal_virus = parser_virus_virustotal(virustotal_virus_response)
    save_json_response(parsed_virustotal_virus, "virus_virustotal_parsed.json")

except Exception as e:
    import traceback
    print(f"An error occurred: {str(e)}")
    print("\nFull traceback:")
    print(traceback.format_exc())
