from flask import Flask, render_template, request, jsonify, session, send_file
from flask_session import Session
import re
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import timedelta
from waitress import serve
import hashlib
import os
import threading
from dotenv import find_dotenv, load_dotenv
from markupsafe import escape

from src.check_ip import check_ip
from src.check_virus import check_virus
from src.check_domain import check_domain
from src.bedrock_claude_service import invoke_bedrock_model
from src.database_mgmt import insert_or_update_ioc_item, insert_or_update_subscription_item, fetch_table, delete_old_records, delete_records_by_subscription_email, search_searched_query_by_ioc_id, search_attributes_by_ioc_id
from src.email_notifier import send_email
from src.compare_result import compare_dicts
from xhtml2pdf import pisa
import io

#### Regex for IPv4, Domain, SHA256 and Email
IPV4_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
DOMAIN_REGEX = r'^(?!.*\.(html|css|js)$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
# Combined regex for MD5, SHA1, or SHA256
HASH_REGEX = re.compile(r'^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}(?:[a-fA-F0-9]{24})?)?$')
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

### Define how many days to send report
NOTIFIED_DAYS = 7

app = Flask(__name__)

# Configure session to use filesystem
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

## local local environment
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

token_secret_key = os.getenv('SECRET_KEY')  # A secret key for generate token

# Define where to store the uploaded files
UPLOAD_FOLDER = 'tmp'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Set max file upload size (e.g., 16 MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

LOG_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
MALICIOUS_FILE_SIZE = 16 * 1024 * 1024  # 16 MB
def background_send_multiple_email(email_addr, ioc_list, file_name):

    # Create an empty list to hold dictionaries of result
    list_of_results = []
    ioc_names = []
    list_of_external_links = []
    ioc_summaries = []

    for searched_query in (ioc_list):
        result = None
        if re.match(IPV4_REGEX, searched_query):
            result = check_ip(searched_query)
            ioc_summary = invoke_bedrock_model(f'IP {searched_query}', result)

        elif re.match(DOMAIN_REGEX, searched_query):
            result = check_domain(searched_query)
            ioc_summary = invoke_bedrock_model(f'domain {searched_query}', result)

        elif re.match(HASH_REGEX, searched_query):
            result = check_virus(searched_query)
            ioc_summary = invoke_bedrock_model(f'hash {searched_query}', result)

        if result is not None:

            insert_or_update_ioc_item(searched_query = searched_query, attributes = result[0])
            list_of_results.append(result[0])
            ioc_names.append(searched_query)
            list_of_external_links.append(result[3])
            ioc_summaries.append(ioc_summary)
        else:
            print(f'No result for {searched_query}')
            pass

    ### create email body with query result
    data = {
        'datasets': list_of_results,
        'ioc_names': ioc_names,
        'list_of_external_links': list_of_external_links,
        'summaries': ioc_summaries
    }

    subject = f"Report of {file_name}"

    with app.app_context():
        body = render_template('email_template.html', **data, zip=zip)

    send_email(email_addr, subject, body)
    # print(f'Send email to {email_addr} for {searched_query} successfully!')

# Define to send email to all subscribers
def send_email_to_subscribers():

    # Delete old records in ioc table before sending out email
    delete_old_records('subscription_prd', NOTIFIED_DAYS)

    # Query all records from subscription table
    success, items = fetch_table('subscription_prd')
    
    if success:

        # find all iocs in subscription table
        ioc_ids = {item['ioc_id'] for item in items if 'ioc_id' in item}

        pre_attributes_list = []

        saved_external_links = []

        for ioc_id in ioc_ids:

            success_ioc, searched_query = search_searched_query_by_ioc_id(ioc_id)

            if success_ioc:

                if re.match(IPV4_REGEX, searched_query):

                    result = check_ip(searched_query)    

                elif re.match(DOMAIN_REGEX, searched_query):

                    result = check_domain(searched_query)

                elif re.match(HASH_REGEX, searched_query):

                    result = check_virus(searched_query)

                if result:

                    # save previous attribute in the list pre_attributes_list
                    success_attributes, pre_attributes = search_attributes_by_ioc_id(ioc_id)

                    if success_attributes:

                        pre_attributes_list.append({ioc_id: pre_attributes})

                    else:

                        pre_attributes_list.append({ioc_id: {}})

                    insert_or_update_ioc_item(searched_query = searched_query, attributes = result[0])

                    saved_external_links.append({ioc_id: result[3]})

        # print(pre_attributes_list)

        email_list = {item['subscription_email'] for item in items if 'subscription_email' in item}

        for email in email_list:

            if email:
                           
                with app.app_context():
                    # Create a simple token for unscribscirbe email
                    token = hashlib.sha256(f"{email}{token_secret_key}".encode()).hexdigest()
                    # print(base_url)
                    unsubscribe_link = f'{base_url}/unsubscribe/{token}'
                    # print(unsubscribe_link)

                ioc_ids_for_email = {item['ioc_id'] for item in items if item.get('subscription_email') == email}

                # print(ioc_ids_for_email)

                # Create an empty list to hold dictionaries of result
                list_of_results = []
                ioc_names = []
                list_of_external_links = []

                for ioc_id in ioc_ids_for_email:

                    success_attributes, attributes = search_attributes_by_ioc_id(ioc_id)
                    success_ioc, searched_query = search_searched_query_by_ioc_id(ioc_id)

                    for pre_item in pre_attributes_list:

                        if ioc_id in pre_item:

                            pre_attributes = pre_item[ioc_id]

                    for external_links in saved_external_links:

                        if ioc_id in external_links:

                            list_of_external_links.append(external_links[ioc_id])

                    if success_attributes:

                        # print(pre_attributes)
                        # print(attributes)
                        attributes_with_diff = compare_dicts(attributes, pre_attributes)
                        # print(attributes_with_diff)

                        list_of_results.append(attributes_with_diff)
                        ioc_names.append(searched_query)

                subject = f"Report from IntelligenceHub"

                ### create email body with query result and unsubscribe_link
                data = {
                    'datasets': list_of_results,
                    'ioc_names': ioc_names,
                    'unsubscribe_link': unsubscribe_link,
                    'list_of_external_links': list_of_external_links
                }
                with app.app_context():
                    body = render_template('subscription_email.html', **data, zip=zip)

                send_email(email, subject, body)
                # print("Send email successfully")

# Function to check if an IP address is private
def is_private_ip(ip):
    private_ip_ranges = [
        re.compile(r'^10\.'),  # 10.0.0.0 - 10.255.255.255
        re.compile(r'^127\.'),  # 127.0.0.0 - 127.255.255.255
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # 172.16.0.0 - 172.31.255.255
        re.compile(r'^192\.168\.'),  # 192.168.0.0 - 192.168.255.255
    ]
    return any(regex.match(ip) for regex in private_ip_ranges)

# Function to check if a domain name is legitimate
def is_legit_domain(domain):
    legit_domains = [
        #re.compile(r'\.com$'),
        #re.compile(r'\.org$'),
        #re.compile(r'\.net$'),
        re.compile(r'\.edu$'),
        re.compile(r'\.gov$'),
    ]
    return any(regex.search(domain) for regex in legit_domains)

# Set up the scheduler
scheduler = BackgroundScheduler()

# Schedule the task to run one day
scheduler.add_job(func=send_email_to_subscribers, trigger="interval", hours = 24)

# Start the scheduler
scheduler.start()

app.secret_key = os.getenv('SECRET_KEY')  # Required to use sessions

app.permanent_session_lifetime = timedelta(minutes=30)  # setting session lifetime to 30 minutes

# Declare a global variable
base_url = None

@app.before_request
def set_global_base_url():
    global base_url  # Access the global variable
    # base_url = f'{request.scheme}://{request.host}'  # Set it dynamically from the request

    base_url = 'https://www.intelligencehub.us'

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():

    #### --- Start --- Used for generanting unsubscriber token URL
    # app.config['APPLICATION_ROOT'] = '/'  # Used for generante unsubscriber token URL
    # app.config['SERVER_NAME'] = request.host
    # app.config['PREFERRED_URL_SCHEME'] = request.scheme
    #### --- End --- Used for generanting unsubscriber token URL

    # print(base_url)

    selected_choice = 'first'

    session.permanent = True  # This makes the session permanent
    default_email_addr = session.get('default_email_addr', '')

    result = {}
    enter_email = False
    message = ""
    external_links = {}
    report_button = False
    ioc_summary = ""
    hash= ""

    if request.method == 'POST':

        # Get the selected option from the form
        selected_choice = request.form.get('choice')

        if selected_choice == 'first':

            text_input = "" 

            if request.form.get('text-input'):

                text_input = escape(request.form.get('text-input'))
                session['ioc'] = text_input

            if re.match(IPV4_REGEX, text_input):

                ip_address = text_input

                result, enter_email, message, external_links = check_ip(ip_address)

                ### Save IOC and IOC result to database

                insert_or_update_ioc_result = insert_or_update_ioc_item(searched_query = ip_address, attributes = result)

                session['insert_or_update_ioc_result'] = insert_or_update_ioc_result

                session['search_result'] = result

                ioc_summary = invoke_bedrock_model(f'IP {ip_address}', result)
                session['ioc_summary'] = ioc_summary

                report_button = True

            elif re.match(DOMAIN_REGEX, text_input):

                domain_name = text_input

                result, enter_email, message, external_links = check_domain(domain_name)

                ### Save IOC and IOC result to database

                insert_or_update_ioc_result = insert_or_update_ioc_item(searched_query = domain_name, attributes = result)

                session['insert_or_update_ioc_result'] = insert_or_update_ioc_result

                session['search_result'] = result

                ioc_summary = invoke_bedrock_model(f'domain {domain_name}', result)
                session['ioc_summary'] = ioc_summary

                report_button = True
                
            elif re.match(HASH_REGEX, text_input):

                hash = text_input

                result, enter_email, message, external_links = check_virus(hash)
                
                ### Save IOC and IOC result to database

                insert_or_update_ioc_result = insert_or_update_ioc_item(searched_query = hash, attributes = result)

                session['insert_or_update_ioc_result'] = insert_or_update_ioc_result

                session['search_result'] = result

                ioc_summary = invoke_bedrock_model(f'hash {hash}', result)
                session['ioc_summary'] = ioc_summary

                report_button = True

            else:
                if not text_input == '':
                    message = f"<p style='color: red'>Invalid Input: {text_input}</p>\n"

        if selected_choice == 'second':
                
            # Get the file from the file input
            file = request.files.get('file-upload')
            if file:
                # Check the file size
                if file.content_length > MALICIOUS_FILE_SIZE:  # 16 MB
                    message = "File size exceeds the max limit."
                else:
                    server_path = os.getcwd()

                    # Save the uploaded file
                    file_path = os.path.join(server_path, app.config['UPLOAD_FOLDER'], file.filename)

                    # Make sure the upload folder exists, create it if it doesn't
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)

                    file.save(file_path)

                    result, enter_email, message, external_links = check_virus(file_path)
                    
                    os.remove(file_path)


                    if 'Sha-256' in result:

                        hash = result['Sha-256']['Result']

                        session['ioc'] = hash

                        insert_or_update_ioc_result = insert_or_update_ioc_item(searched_query = hash, attributes = result)

                        session['insert_or_update_ioc_result'] = insert_or_update_ioc_result

                    session['search_result'] = result
                    ioc_summary = invoke_bedrock_model(f'hash {hash}', result)
                    session['ioc_summary'] = ioc_summary
                    report_button = True

        if selected_choice == 'third':

            # Regular expressions for IP addresses and domain names in a file
            ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            domain_regex = r'\b(?:[a-zA-Z0-9-]+\.)+(?!html|css|js\b)[a-zA-Z]{2,}\b'

            # Get the logs file from the file input
            log_file = request.files.get('log-file-upload')

            if log_file:
                # Check the file size
                if log_file.content_length > LOG_FILE_SIZE:  # 2 MB
                    message = "File size exceeds the max limit."
                else:
                    email_addr_log_report = request.form.get('email_addr_log_report')

                    # Check whether enter email address for receiving report or not
                    if email_addr_log_report:

                        log_data = log_file.read().decode('utf-8')

                        # Filter out private IP addresses
                        ip_addresses = re.findall(ip_regex, log_data)
                        public_ip_addresses = [ip for ip in ip_addresses if not is_private_ip(ip)]

                        # Filter out legitimate domain names
                        domain_names = re.findall(domain_regex, log_data)
                        non_legit_domain_names = [domain for domain in domain_names if not is_legit_domain(domain)]

                        # Remove duplicates by converting to sets, then back to lists
                        unique_ips = list(set(public_ip_addresses))
                        unique_domains = list(set(non_legit_domain_names))
                        # Combine the two lists
                        combined_list = unique_ips + unique_domains

                        message = f'Found below IOCs in the logs file, will send the report to {email_addr_log_report} shortly:<br> IP Addresses: {unique_ips}<br> Domain Names: {unique_domains}'

                        # Send email for result
                        thread_background = threading.Thread(target=background_send_multiple_email, args=(email_addr_log_report, combined_list, log_file.filename))
                        thread_background.start()

                    else:
                        message = 'Please enter valid email address for receiving report.'

    return render_template(
        "index.html",
        selected_choice = selected_choice,
        default_email_addr = default_email_addr,
        message = message,
        enter_email = enter_email,
        data = result,
        external_links = external_links,
        report_button = report_button,
        summary = ioc_summary
    )

# Subscribe link
@app.route('/subscribe', methods=['POST'])
def save_email():

    email_addr = request.form.get('email_addr')

    ioc = session['ioc']

    # Success or failure in saving
    if re.match(EMAIL_REGEX, email_addr):
        # If correct email format 
        session['default_email_addr'] = email_addr
        
        result_ioc, msg = session['insert_or_update_ioc_result']
        
        if result_ioc:

            result_subscription, msg = insert_or_update_subscription_item(searched_query = ioc, subscription_email = email_addr)

            if result_subscription:

                # Prompt save successful
                return jsonify({'success': True, 'message': msg})
            
            else:

                # Prompt failure in saving
                return jsonify({'success': False, 'message': msg})

        else:

            # Prompt failure in saving
            return jsonify({'success': False, 'message': msg})
    else:

        return jsonify({'success': False, 'message': 'Wrong email format'})

# Unsubscribe link
@app.route('/unsubscribe/<token>')
def unsubscribe(token):

    if request.method == 'GET':

        removed_email_addr = None

        # Query all
        success, items = fetch_table('subscription_prd')

        if success:

            for item in items:

                email = item.get('subscription_email')

                # Check all email and compare the token to determine which email to delete
                if token == hashlib.sha256(f"{email}{token_secret_key}".encode()).hexdigest():
                    removed_email_addr = email

        delete_records_by_subscription_email('subscription_prd', removed_email_addr)

        return render_template(
            "index.html",
            selected_choice = 'first',
            message = 'Your email has been removed successfully',
        )

@app.route('/about')
def about():
    return render_template(
        "about.html",
    )

@app.route('/contact', methods=['GET', 'POST'])
def contact():

    email_sent = False

    if request.method == 'POST':

        email_addr = "intelligencehub.cal@gmail.com"

        user_name = request.form.get('name')

        user_email = request.form.get('email')

        message = request.form.get('message')

        body = f"User email:<br> {user_email}<br> Message:<br> {message}"

        subject = f"Contact request from {user_name}"

        send_email(email_addr, subject, body)

        email_sent = True

    return render_template(
        "contact.html",
        email_sent = email_sent
    )

@app.route('/download_pdf', methods=['GET'])
def download_pdf():
    result = session.get('search_result', {})
    summary = session.get('ioc_summary', '')
    data = {'result': result, 'summary': summary}
    if not result:
        return jsonify({'error': 'No search results available'}), 400

    html = render_template('pdf_report.html', data=data)

    pdf = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        html,
        dest=pdf,
        encoding='UTF-8',
        options={
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
        }
    )

    if pisa_status.err:
        return jsonify({'error': 'PDF generation failed'}), 500

    pdf.seek(0)
    return send_file(pdf, download_name='search_results.pdf', as_attachment=True, mimetype='application/pdf')

if __name__ == "__main__":
    print("Starting application.......")

    # use waitress.serve
    print("Server is running on http://localhost:8000")
    serve(app, host="0.0.0.0", port=8000)

    print("Shutting down application")
