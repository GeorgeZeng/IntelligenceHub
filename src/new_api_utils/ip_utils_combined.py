
import os
import requests
import cloudmersive_validate_api_client
from cloudmersive_validate_api_client.rest import ApiException

def check_ip_abuseipdb(ip_address):
    abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90&verbose"
    headers = {
        "Key": abuseipdb_api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return {
            "success": True,
            "source": "abuseipdb",
            "data": response.json(),
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "source": "abuseipdb",
            "data": None,
            "error": str(e)
        }

def check_ip_criminalip(ip_address):
    criminal_ip_api_key = os.getenv("CriminalIP_API_Key")
    url = f"https://api.criminalip.io/v1/asset/ip/report/summary?ip={ip_address}"
    headers = {
        "x-api-key": criminal_ip_api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return {
            "success": True,
            "source": "criminalip",
            "data": response.json(),
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "source": "criminalip",
            "data": None,
            "error": str(e)
        }

def check_ip_cloudmersive(ip_address):
    configuration = cloudmersive_validate_api_client.Configuration()
    configuration.api_key['Apikey'] = os.getenv("CLOUDMERSIVE_API_KEY")

    ip_api_instance = cloudmersive_validate_api_client.IPAddressApi(cloudmersive_validate_api_client.ApiClient(configuration))

    try:
        # Single API call that includes bot check, tor node check, threat check, and location
        ip_intelligence = ip_api_instance.i_p_address_ip_intelligence(ip_address)
        
        result = {
            'ip_intelligence': {
                'ip_address': ip_address,
                'is_bot': ip_intelligence.is_bot,
                'is_tor_node': ip_intelligence.is_tor_node,
                'is_threat': ip_intelligence.is_threat,
                'is_eu': ip_intelligence.is_eu,
                'location': ip_intelligence.location.to_dict() if ip_intelligence.location else None,
                'currency_code': ip_intelligence.currency_code,
                'currency_name': ip_intelligence.currency_name,
                'region_area': ip_intelligence.region_area,
                'subregion_area': ip_intelligence.subregion_area
            }
        }

        # Only perform domain lookups if specifically needed
        if os.getenv("CLOUDMERSIVE_DOMAIN_LOOKUP", "false").lower() == "true":
            domain_api_instance = cloudmersive_validate_api_client.DomainApi(cloudmersive_validate_api_client.ApiClient(configuration))
            reverse_dns_response = ip_api_instance.i_p_address_reverse_domain_lookup(ip_address)
            result['reverse_dns'] = reverse_dns_response.to_dict()
            
            if reverse_dns_response.successful and reverse_dns_response.host_name:
                domain_quality = domain_api_instance.domain_quality_score(reverse_dns_response.host_name)
                result['domain_quality'] = domain_quality.to_dict()

        return {
            "success": True,
            "source": "cloudmersive",
            "data": result,
            "error": None
        }
    except ApiException as e:
        return {
            "success": False,
            "source": "cloudmersive",
            "data": None,
            "error": str(e)
        }

def check_ip_virustotal(ip_address):
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    base_url = "https://www.virustotal.com/api/v3/ip_addresses"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }
    try:
        response = requests.get(f"{base_url}/{ip_address}", headers=headers)
        response.raise_for_status()
        
        data = response.json()
        return {
            "success": True,
            "source": "virustotal",
            "data": data,
            "error": None
        }

    except Exception as e:  # Changed from ApiException
        return {
            "success": False,
            "source": "virustotal",
            "data": None,
            "error": str(e)
        }
