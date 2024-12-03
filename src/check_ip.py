from src.new_api_utils.ip_utils_combined import (
    check_ip_abuseipdb,
    check_ip_criminalip,
    check_ip_virustotal,
    check_ip_cloudmersive
)
from src.new_api_utils.parser_combined import (
    parser_abuseipdb,
    parser_criminalip,
    parser_ip_virustotal,
    parser_ip_cloudmersive
)
from src.response_parser import merge_results, format_display_result, add_source_to_each_data_point

def check_ip(ip_address):
    result = {}
    external_links = {}

    ### AbuseIPDB
    abuseipdb_data = check_ip_abuseipdb(ip_address)
    result = merge_results(result, add_source_to_each_data_point(parser_abuseipdb(abuseipdb_data), 'AbuseIPDB'))
    link_for_abuseipdb = {'AbuseIPDB': f"https://www.abuseipdb.com/check/{ip_address}"}
    external_links = {**external_links, **link_for_abuseipdb}

    ## CriminalIP
    criminalip_data = check_ip_criminalip(ip_address)
    result = merge_results(result, add_source_to_each_data_point(parser_criminalip(criminalip_data), 'CriminalIP'))
    link_for_criminalip = {'CriminalIP': f"https://www.criminalip.io/asset/report/{ip_address}"}
    external_links = {**external_links, **link_for_criminalip}

    ### VirusTotal
    virustotal_data = check_ip_virustotal(ip_address)
    result = merge_results(result, add_source_to_each_data_point(parser_ip_virustotal(virustotal_data), 'VirusTotal'))
    link_for_virustotal = {'VirusTotal': f"https://www.virustotal.com/gui/ip-address/{ip_address}"}
    external_links = {**external_links, **link_for_virustotal}

    ### Cloudmersive
    cloudmersive_data = check_ip_cloudmersive(ip_address)
    result = merge_results(result, add_source_to_each_data_point(parser_ip_cloudmersive(cloudmersive_data), 'Cloudmersive'))
    link_for_cloudmersive = {'Cloudmersive': "https://api.cloudmersive.com/docs/validate.asp#tag-IPAddress"}
    external_links = {**external_links, **link_for_cloudmersive}

    ### format result for display in HTML
    result = format_display_result(result)

    message = f"Result of {ip_address}"
    enter_email = True
    return result, enter_email, message, external_links

if __name__ == "__main__":
    print("*** Check IP ***")
    ip_address = input("\nPlease enter an IP address: ")
    result_check_ip = check_ip(ip_address)
    print(result_check_ip[0])

