
import os
import requests
import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException

def check_virus_cloudmersive(file_path):
    configuration = cloudmersive_virus_api_client.Configuration()
    configuration.api_key['Apikey'] = os.getenv("CLOUDMERSIVE_API_KEY")

    api_instance = cloudmersive_virus_api_client.ScanApi(cloudmersive_virus_api_client.ApiClient(configuration))

    try:
        api_response = api_instance.scan_file_advanced(file_path)
        result = {
            "id": file_path,
            'is_malicious': not api_response.clean_result,
            'risk_factors': {
                'contains_executable': api_response.contains_executable,
                'contains_invalid_file': api_response.contains_invalid_file,
                'contains_script': api_response.contains_script,
                'contains_password_protected_file': api_response.contains_password_protected_file,
                'contains_restricted_file_format': api_response.contains_restricted_file_format,
            },
            'file_info': {
                'verified_file_format': api_response.verified_file_format
            },
            'threats': [
                {'file_name': virus.file_name, 'threat_name': virus.virus_name}
                for virus in api_response.found_viruses
            ] if api_response.found_viruses else []
        }
        return {
            'source': 'cloudmersive',
            'success': True,
            'data': result,
            'error': None
        }
    except ApiException as e:
        return {
            'source': 'cloudmersive',
            'success': False,
            'data': None,
            'error': str(e)
        }

def check_virus_virustotal(hash_value):
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    base_url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    try:
        # Get basic file info
        basic_response = requests.get(
            f"{base_url}/{hash_value}",
            headers=headers,
            params={"include": "last_analysis_results,last_analysis_stats,type_description,size,type_tag,times_submitted,total_votes,reputation"}
        )
        basic_response.raise_for_status()
        
        # Get behavior info
        behavior_response = requests.get(
            f"{base_url}/{hash_value}/behaviour",
            headers=headers
        )
        behavior_data = behavior_response.json() if behavior_response.status_code == 200 else {}
        
        basic_data = basic_response.json()
        attributes = basic_data.get('data', {}).get('attributes', {})
        behavior_attributes = behavior_data.get('data', {}).get('attributes', {})
        
        # Summarize threats by counting occurrences
        threat_counts = {}
        for engine, result in attributes.get('last_analysis_results', {}).items():
            if result['category'] == 'malicious':
                threat_name = result.get('result', 'unknown')
                threat_counts[threat_name] = threat_counts.get(threat_name, 0) + 1
        
        result = {
            'id': hash_value,
            'is_malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0) > 0,
            'risk_factors': {
                'total_votes_malicious': attributes.get('total_votes', {}).get('malicious', 0),
                'reputation': attributes.get('reputation', 0),
                'suspicious_count': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                'sandbox_verdicts': behavior_attributes.get('verdicts', {}),
                'mitre_attack_techniques': behavior_attributes.get('mitre_attack_techniques', []),
                'sigma_analysis_summary': behavior_attributes.get('sigma_analysis_summary', {})
            },
            'file_info': {
                'type_description': attributes.get('type_description'),
                'size': attributes.get('size'),
                'file_type': attributes.get('type_tag'),
                'times_submitted': attributes.get('times_submitted'),
                'creation_date': attributes.get('creation_date'),
                'first_submission_date': attributes.get('first_submission_date'),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'names': attributes.get('names', []),
                'signature_info': attributes.get('signature_info', {})
            },
            'threats': threat_counts or "None found"
        }
        return {
            'source': 'virustotal',
            'success': True,
            'data': result,
            'error': None
        }
    except Exception as e:
        return {
            'source': 'virustotal',
            'success': False,
            'data': None,
            'error': str(e)
        }