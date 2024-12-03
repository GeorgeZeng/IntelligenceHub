
import os
import requests
import cloudmersive_validate_api_client
from cloudmersive_validate_api_client.rest import ApiException

def check_domain_cloudmersive(domain):
    configuration = cloudmersive_validate_api_client.Configuration()
    configuration.api_key['Apikey'] = os.getenv("CLOUDMERSIVE_API_KEY")

    # Create API instances
    domain_api = cloudmersive_validate_api_client.DomainApi(cloudmersive_validate_api_client.ApiClient(configuration))
    lead_api = cloudmersive_validate_api_client.LeadEnrichmentApi(cloudmersive_validate_api_client.ApiClient(configuration))

    try:
        # Get domain quality score and validity
        quality_score = domain_api.domain_quality_score(domain)
        domain_validity = domain_api.domain_check(domain)
        
        # Create lead enrichment request
        lead_request = cloudmersive_validate_api_client.LeadEnrichmentRequest(
            company_domain_name=domain
        )
        
        # Get enrichment data
        lead_info = lead_api.lead_enrichment_enrich_lead(lead_request)
        
        result = {
            'source': 'cloudmersive',
            'success': True,
            'data': {
                'domain': domain,
                'quality_score': quality_score.domain_quality_score,
                'valid_domain': domain_validity.valid_domain,
                'whois_info': {
                    'registrant_name': lead_info.contact_first_name,  # Changed from whois_info
                    'registrant_organization': lead_info.company_name,
                    'registrant_email': lead_info.contact_business_email,
                    'registrant_street': lead_info.company_street,
                    'registrant_city': lead_info.company_city,
                    'registrant_state_or_province': lead_info.company_state_or_province,
                    'registrant_postal_code': lead_info.company_postal_code,
                    'registrant_country': lead_info.company_country,
                    'registrant_raw_address': f"{lead_info.company_street}, {lead_info.company_city}, {lead_info.company_state_or_province}, {lead_info.company_postal_code}, {lead_info.company_country}",
                    'registrant_telephone': lead_info.company_telephone,
                    'whois_server': None,  # Not available in lead enrichment
                    'raw_text_record': None,  # Not available in lead enrichment
                    'created_dt': None  # Not available in lead enrichment
                }
            },
            'error': None 
        }
        return result
    except ApiException as e:
        return {
            'source': 'cloudmersive',
            'success': False,
            'error': str(e),
            'data': None
        }

def check_domain_virustotal(domain):
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return {
            'source': 'virustotal',
            'success': True,
            'data': response.json(),
            'error': None 
        }
    except requests.exceptions.RequestException as e:
        return {
            'source': 'virustotal',
            'success': False,
            'data': None,
            'error': str(e)
        }
