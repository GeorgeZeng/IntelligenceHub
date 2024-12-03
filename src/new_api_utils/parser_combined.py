from typing import Dict, Any, Optional, List, Union
from datetime import datetime

def format_timestamp(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else None

key_mapping = {
    # Identity & Basic Info
    'source': 'Source',
    'id': 'Identifier',
    'tags': 'Tags',
    'domain': 'Domain',
    'size': 'Size',
    'names': 'Names',
    
    # Status & Reputation
    'reputation': 'Reputation',
    'total_votes': 'Total Votes',
    'is_public': 'Is Public',
    'is_valid': 'Is Valid',
    'is_whitelisted': 'Is Whitelisted',
    'abuse_confidence_score': 'Abuse Confidence Score',
    
    # Analysis Results
    'malicious': 'Malicious',
    'suspicious': 'Suspicious',
    'harmless': 'Harmless',
    'undetected': 'Undetected',
    'timeout': 'Timeout',
    'last_analysis_results': 'Last Analysis Results',
    
    # Timestamps
    'creation_date': 'Creation Date',
    'last_update_date': 'Last Update Date',
    'last_modification_date': 'Last Modification Date',
    'first_submission_date': 'First Submission Date',
    'last_analysis_date': 'Last Analysis Date',
    'last_reported_at': 'Last Reported At',
    'times_submitted': 'Times Submitted',
    
    # Location Information
    'country_code': 'Country Code',
    'country_name': 'Country',
    'country': 'Country',
    'city': 'City',
    'region_code': 'Region Code',
    'region_name': 'Region',
    'zip_code': 'Zip Code',
    'timezone': 'Timezone',
    'latitude': 'Latitude',
    'longitude': 'Longitude',
    'continent': 'Continent',
    'region_area': 'Region Area',
    'subregion_area': 'Subregion Area',
    'is_eu': 'Is EU',
    'currency_code': 'Currency Code',
    'currency_name': 'Currency Name',
    
    # Network Information
    'asn': 'ASN',
    'as_owner': 'Owner',
    'network': 'Network',
    'isp': 'ISP',
    'ip_address': 'IP Address',
    'ip_version': 'IP Version',
    'hostnames': 'Hostnames',
    'reverse_dns_hostname': 'Reverse DNS Hostname',
    'usage_type': 'Usage Type',
    
    # Threat Information
    'is_threat': 'Is Threat',
    'is_bot': 'Is Bot',
    'is_tor_node': 'Is Tor Node',
    'is_tor': 'Is Tor',
    'threat_type': 'Threat Type',
    'total_reports': 'Total Reports',
    'num_distinct_users': 'Number of Distinct Users',
    
    # Domain & WHOIS Information
    'whois': 'WHOIS',
    'last_dns_records': 'Last DNS Records',
    'categories': 'Categories',
    'registrar': 'Registrar',
    'registrant_name': 'Registrant Name',
    'registrant_organization': 'Registrant Organization',
    'registrant_email': 'Registrant Email',
    'registrant_country': 'Registrant Country',
    'registrant_street': 'Registrant Street',
    'registrant_city': 'Registrant City',
    'registrant_state': 'Registrant State',
    'registrant_phone': 'Registrant Phone',
    'registrant_postal_code': 'Zip Code',
    'registrant_raw_address': 'Registrant Raw Address',
    
    # File Analysis
    'type_description': 'Type Description',
    'clean_result': 'Clean Result',
    'contains_executable': 'Contains Executable',
    'contains_invalid_file': 'Contains Invalid File',
    'contains_script': 'Contains Script',
    'contains_password_protected_file': 'Contains Password Protected File',
    'contains_restricted_file_format': 'Contains Restricted File Format',
    'verified_file_format': 'Verified File Format',
    'found_viruses': 'Found Viruses',
}

def parser_abuseipdb(data: Dict[str, Any]) -> Dict[str, Any]:
    if 'data' in data and 'data' in data['data']:  # Check for both levels
        attributes = data['data']['data']  # Access nested data
        return {
            # Identity & Basic Info
            key_mapping['source']: 'abuseipdb',
            key_mapping['id']: attributes.get('ipAddress'),
            key_mapping['domain']: attributes.get('domain'),
            
            # Status & Reputation
            key_mapping['is_public']: attributes.get('isPublic'),
            key_mapping['is_whitelisted']: attributes.get('isWhitelisted'),
            key_mapping['abuse_confidence_score']: attributes.get('abuseConfidenceScore'),
            
            # Location Information
            key_mapping['country_name']: attributes.get('countryName'),
            key_mapping['country_code']: attributes.get('countryCode'),
            
            # Network Information
            key_mapping['ip_version']: attributes.get('ipVersion'),
            key_mapping['isp']: attributes.get('isp'),
            key_mapping['hostnames']: attributes.get('hostnames', [])[0] if attributes.get('hostnames') else "",
            key_mapping['usage_type']: attributes.get('usageType'),
            
            # Threat Information
            key_mapping['is_tor']: attributes.get('isTor'),
            key_mapping['total_reports']: attributes.get('totalReports'),
            key_mapping['num_distinct_users']: attributes.get('numDistinctUsers'),
            key_mapping['last_reported_at']: attributes.get('lastReportedAt'),
        }
    return {}

def parser_criminalip(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    data = raw_data['data']
    if not data:
        return {}

    flat_data = {
        key_mapping['tags']: data.get('tags', []),
        'issue': data.get('issue', []),
        'ip_scoring_inbound': data.get('ip_scoring', {}).get('inbound', None),
        'ip_scoring_outbound': data.get('ip_scoring', {}).get('outbound', None),
        'ip_scoring_is_malicious': data.get('ip_scoring', {}).get('is_malicious', None),
        'current_open_ports_TCP': '\n'.join(f"port: {port['port']}, has_vulnerability: {port['has_vulnerability']}" for port in data.get('current_open_ports', {}).get('TCP', [])),
        'current_open_ports_UDP': '\n'.join(f"port: {port['port']}, has_vulnerability: {port['has_vulnerability']}" for port in data.get('current_open_ports', {}).get('UDP', [])),
    }

    summary = data.get('summary', {})
    if summary:
        connection = summary.get('connection', {})
        for key, value in connection.items():
            flat_data[key] = value

        detection = summary.get('detection', {})
        for key, value in detection.items():
            flat_data[key] = value

        security = summary.get('security', {})
        for key, value in security.items():
            flat_data[key] = value

        flat_data['dns_service'] = summary.get('dns_service', {})

    return flat_data

def parser_ip_cloudmersive(data: Dict[str, Any]) -> Dict[str, Any]:
    if 'data' not in data:
        return {}
    
    # Get the data section if it exists
    data = data.get('data', {})
    if not data:
        return {}
    return {
        # Identity & Basic Info
        key_mapping['source']: 'cloudmersive',
        key_mapping['id']: data.get('ip_intelligence', {}).get('ip_address'),
        
        # Location Information
        key_mapping['country_code']: data.get('ip_intelligence', {}).get('location', {}).get('country_code'),
        key_mapping['country_name']: data.get('ip_intelligence', {}).get('location', {}).get('country_name'),
        key_mapping['city']: data.get('ip_intelligence', {}).get('location', {}).get('city'),
        key_mapping['region_code']: data.get('ip_intelligence', {}).get('location', {}).get('region_code'),
        key_mapping['region_name']: data.get('ip_intelligence', {}).get('location', {}).get('region_name'),
        key_mapping['zip_code']: data.get('ip_intelligence', {}).get('location', {}).get('zip_code'),
        key_mapping['timezone']: data.get('ip_intelligence', {}).get('location', {}).get('timezone_standard_name'),
        key_mapping['latitude']: data.get('ip_intelligence', {}).get('location', {}).get('latitude'),
        key_mapping['longitude']: data.get('ip_intelligence', {}).get('location', {}).get('longitude'),
        key_mapping['is_eu']: data.get('ip_intelligence', {}).get('is_eu'),
        key_mapping['currency_code']: data.get('ip_intelligence', {}).get('currency_code'),
        key_mapping['currency_name']: data.get('ip_intelligence', {}).get('currency_name'),
        key_mapping['region_area']: data.get('ip_intelligence', {}).get('region_area'),
        key_mapping['subregion_area']: data.get('ip_intelligence', {}).get('subregion_area'),
        
        # Network Information
        key_mapping['reverse_dns_hostname']: data.get('reverse_dns', {}).get('host_name'),
        
        # Threat Information
        key_mapping['is_bot']: data.get('ip_intelligence', {}).get('is_bot'),
        key_mapping['is_tor_node']: data.get('ip_intelligence', {}).get('is_tor_node'),
        key_mapping['is_threat']: data.get('ip_intelligence', {}).get('is_threat'),
        key_mapping['threat_type']: data.get('ip_threat', {}).get('threat_type'),
    }

def parser_ip_virustotal(data: Dict[str, Any]) -> Dict[str, Any]:
    data = data.get("data", {}).get("data", {})
    
    # Summarize last_analysis_results
    last_analysis_results = data.get("attributes", {}).get("last_analysis_results", {})
    category_counts = {}
    result_counts = {}
    
    for result in last_analysis_results.values():
        category = result.get('category', '')
        
        category_counts[category] = category_counts.get(category, 0) + 1
    
    return {
        key_mapping['source']: 'virustotal',
        key_mapping['id']: data.get("id"),
        key_mapping['asn']: data.get("attributes", {}).get("asn"),
        key_mapping['as_owner']: data.get("attributes", {}).get("as_owner"),
        key_mapping['country']: data.get("attributes", {}).get("country"),
        key_mapping['continent']: data.get("attributes", {}).get("continent"),
        key_mapping['network']: data.get("attributes", {}).get("network"),
        key_mapping['reputation']: data.get("attributes", {}).get("reputation"),
        key_mapping['last_modification_date']: format_timestamp(data.get("attributes", {}).get("last_modification_date")),
        key_mapping['total_votes']: f"harmless: {data.get('attributes', {}).get('total_votes', {}).get('harmless', 0)}; malicious: {data.get('attributes', {}).get('total_votes', {}).get('malicious', 0)}",
        key_mapping['last_analysis_results']: "; ".join(f"{category}: {count}" for category, count in category_counts.items()),
    }

def parser_domain_cloudmersive(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if data is None or 'data' not in data:
        return None
    
    data = data['data']
    whois_info = data.get('whois_info', {})
    
    return {
        # Identity & Basic Info
        key_mapping['source']: 'cloudmersive',
        key_mapping['id']: data.get("domain"),
        
        # Domain & WHOIS Information
        key_mapping['registrant_name']: whois_info.get('registrant_name'),
        key_mapping['registrant_organization']: whois_info.get('registrant_organization'),
        key_mapping['registrant_email']: whois_info.get('registrant_email'),
        key_mapping['registrant_street']: whois_info.get('registrant_street'),
        key_mapping['registrant_city']: whois_info.get('registrant_city'),
        key_mapping['registrant_state']: whois_info.get('registrant_state_or_province'),
        key_mapping['registrant_postal_code']: whois_info.get('registrant_postal_code'),
        key_mapping['registrant_country']: whois_info.get('registrant_country'),
        key_mapping['registrant_raw_address']: whois_info.get('registrant_raw_address'),
        key_mapping['registrant_phone']: whois_info.get('registrant_telephone'),
    }

def parser_domain_virustotal(data: Dict[str, Any]) -> Dict[str, Any]:
    inner_data = data.get("data", {}).get("data", {})
    attributes = inner_data.get("attributes", {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    votes = attributes.get('total_votes', {})
    
    mappings = {
        # Identity & Basic Info
        key_mapping['source']: 'virustotal',
        key_mapping['id']: inner_data.get("id"),
        
        # Status & Reputation
        key_mapping['reputation']: attributes.get("reputation"),
        key_mapping['total_votes']: f"harmless: {votes.get('harmless', 0)}, malicious: {votes.get('malicious', 0)}",
        
        # Analysis Results
        key_mapping['malicious']: last_analysis_stats.get("malicious"),
        key_mapping['suspicious']: last_analysis_stats.get("suspicious"),
        key_mapping['undetected']: last_analysis_stats.get("undetected"),
        key_mapping['harmless']: last_analysis_stats.get("harmless"),
        key_mapping['timeout']: last_analysis_stats.get("timeout"),
        
        # Timestamps
        key_mapping['creation_date']: format_timestamp(attributes.get("creation_date")),
        key_mapping['last_update_date']: format_timestamp(attributes.get("last_update_date")),
        
        # Domain & WHOIS Information
        key_mapping['registrar']: attributes.get("registrar"),
        key_mapping['whois']: attributes.get("whois"),
        key_mapping['last_dns_records']: '\n'.join([f"Type: {record.get('type', '')}; {record.get('value', '')}" for record in attributes.get("last_dns_records", [])]) or None,
        key_mapping['categories']: ', '.join([f"{domain}: {category}" for domain, category in attributes.get("categories", {}).items()]) or None,
    }
    
    # Only add non-None and non-empty values to the result
    result = {}
    for key, value in mappings.items():
        if value not in (None, "", [], {}):
            result[key] = value
            
    return result

def parser_virus_cloudmersive(data: Dict[str, Any]) -> Dict[str, Union[bool, List[str], str]]:
    if not data.get('data'):
        return {}
        
    data = data['data']
    return {
        # Identity & Basic Info
        key_mapping['source']: 'cloudmersive',
        key_mapping['id']: data.get('id'),
        
        # File Analysis
        key_mapping['clean_result']: not data.get('is_malicious'),
        key_mapping['contains_executable']: data.get('risk_factors', {}).get('contains_executable'),
        key_mapping['contains_invalid_file']: data.get('risk_factors', {}).get('contains_invalid_file'),
        key_mapping['contains_script']: data.get('risk_factors', {}).get('contains_script'),
        key_mapping['contains_password_protected_file']: data.get('risk_factors', {}).get('contains_password_protected_file'),
        key_mapping['contains_restricted_file_format']: data.get('risk_factors', {}).get('contains_restricted_file_format'),
        key_mapping['verified_file_format']: data.get('file_info', {}).get('verified_file_format'),
        key_mapping['found_viruses']: "None found" if not data.get('threats') else data['threats']
    }

def parser_virus_virustotal(data: Dict[str, Any]) -> Dict[str, Any]:
    file_info = data.get("data", {}).get("file_info", {})
    risk_factors = data.get("data", {}).get("risk_factors", {})
    threats = data.get("data", {}).get("threats", {})
    
    return {
        # Identity & Basic Info
        key_mapping['source']: 'virustotal',
        key_mapping['id']: data.get("data", {}).get("id"),
        key_mapping['size']: file_info.get("size"),
        key_mapping['names']: file_info.get("names", []),
        
        # Status & Reputation
        key_mapping['reputation']: risk_factors.get("reputation"),
        
        # Analysis Results
        key_mapping['malicious']: f"Votes: {risk_factors.get('total_votes_malicious', 0)}",
        key_mapping['suspicious']: f"Votes: {risk_factors.get('suspicious_count', 0)}",
        
        # Timestamps
        key_mapping['times_submitted']: file_info.get("times_submitted"),
        key_mapping['first_submission_date']: format_timestamp(file_info.get("first_submission_date")),
        key_mapping['last_analysis_date']: format_timestamp(file_info.get("last_analysis_date")),
        
        # File Analysis
        key_mapping['type_description']: file_info.get("type_description"),
        key_mapping['found_viruses']: threats if threats else "None found"
    }
