from src.new_api_utils.parser_combined import (
    parser_abuseipdb,
    parser_criminalip,
    parser_ip_virustotal,
    parser_ip_cloudmersive,
    parser_domain_virustotal,
    parser_domain_cloudmersive,
    parser_virus_virustotal,
    parser_virus_cloudmersive
)

def parse_data(data_source, data_type):
    if not data_source:
        return {}

    if data_type == 'ip':
        if 'abuseConfidenceScore' in data_source:
            return parser_abuseipdb(data_source)
        elif 'issues' in data_source:
            return parser_criminalip(data_source)
        elif 'attributes' in data_source:
            return parser_ip_virustotal(data_source)
        elif 'ip_threat' in data_source:
            return parser_ip_cloudmersive(data_source)
            
    elif data_type == 'domain':
        if 'attributes' in data_source:
            return parser_domain_virustotal(data_source)
        elif 'whois_info' in data_source.get('data', {}):
            return parser_domain_cloudmersive(data_source)
            
    elif data_type == 'virus':
        if 'attributes' in data_source:
            return parser_virus_virustotal(data_source)
        elif 'found_viruses' in data_source:
            return parser_virus_cloudmersive(data_source)
            
    return {}

def replace_newline_char(data):
    if isinstance(data, dict):
        return {k: replace_newline_char(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_newline_char(item) for item in data]
    elif isinstance(data, str):
        return data.replace("\n", "<br>")
    else:
        return data

def merge_results(result1, result2):
    merged = result1.copy()
    for key, value in result2.items():
        if key not in merged or merged[key] is None:
            merged[key] = value
        elif isinstance(value, dict) and isinstance(merged[key], dict):
            merged[key] = merge_results(merged[key], value)
    return merged

def format_result(result):
    formatted = {}
    for key, value in result.items():
        formatted_key = key.replace('_', ' ').title()
        if isinstance(value, dict):
            formatted[formatted_key] = format_result(value)
        elif isinstance(value, list):
            formatted[formatted_key] = [format_result(item) if isinstance(item, dict) else item for item in value]
        else:
            formatted[formatted_key] = value
    return formatted

def format_display_result(result):
    formatted = format_result(result)
    return {k: v if not isinstance(v, str) else v.replace('\n', '<br>') for k, v in formatted.items()}

def add_source_to_each_data_point(original_data, source):

    combined_data = {}
    for key, value in original_data.items():
        combined_data[key] = {
            "result": value,
            "source": source
        }

    return combined_data

if __name__ == "__main__":

    print("*** parsing ***")

    # parsed_result = replace_newline_char(parser_ip_result_virustotal(orignal_virustotal))

    # print(parsed_result)

    