from src.new_api_utils.domain_utils_combined import check_domain_virustotal, check_domain_cloudmersive
from src.new_api_utils.parser_combined import parser_domain_virustotal, parser_domain_cloudmersive
from src.response_parser import merge_results, format_display_result, add_source_to_each_data_point

def check_domain(domain):
    result = {}
    enter_email = False
    message = ""
    external_links = {}
    foundData = False

    ### VirusTotal
    try:
        virustotal_data = check_domain_virustotal(domain)
        if virustotal_data['success']:
            message = f"Result of {domain}"
            enter_email = True
            parsed_data = parser_domain_virustotal(virustotal_data)
            result = merge_results(result, add_source_to_each_data_point(format_display_result(parsed_data), 'VirusTotal'))

            link_for_virustotal = {'VirusTotal': f"https://www.virustotal.com/gui/domain/{domain}"}
            external_links = {**external_links, **link_for_virustotal}
            foundData = True
    except Exception as e:
        print(f"Did not get data from VirusTotal for {domain} due to error: {str(e)}")

    try:
        ### Cloudmersive
        cloudmersive_data = check_domain_cloudmersive(domain)
        if cloudmersive_data['success']:
            message = f"Result of {domain}"
            enter_email = True
            parsed_data = parser_domain_cloudmersive(cloudmersive_data)
            result = merge_results(result, add_source_to_each_data_point(parsed_data, 'Cloudmersive'))

            link_for_cloudmersive = {'Cloudmersive': "https://api.cloudmersive.com/docs/validate.asp#tag-Domain"}
            external_links = {**external_links, **link_for_cloudmersive}
            foundData = True
    except Exception as e:
        print(f"Did not get data from cloudmersive for {domain} due to error: {str(e)}")

    if foundData:
        ### format result for display in HTML
        result = format_display_result(result)
        return result, enter_email, message, external_links
    else:
        return None
