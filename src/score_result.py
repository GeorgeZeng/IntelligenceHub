from check_ip import check_ip
from check_domain import check_domain
from check_virus import check_virus
import re

#### Regex for IPv4, Domain, SHA256 and Email
IPV4_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
DOMAIN_REGEX = r'^(?!.*\.(html|css|js)$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
# Combined regex for MD5, SHA1, or SHA256
HASH_REGEX = re.compile(r'^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}(?:[a-fA-F0-9]{24})?)?$')
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

def score_result(result):
    if 'domain' in result:
        return check_domain(result['domain'])
    elif 'ip' in result:
        return check_ip(result['ip'])	
    elif HASH_REGEX.match(result['file_hash']):
        return check_virus(result['file_hash'])
    else:
        return result