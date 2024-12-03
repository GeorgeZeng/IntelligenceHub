## About

This repository contains a Python Flask web application for MICS Fall 2024 Capstone Project.

by Karim Hosn, Yash Singh, Erik Swanson, George Zeng

UC Berkeley

## Features

- Flask-based routing
- Jinja2 template rendering
- Environment configuration
- Easy setup with `venv` and `pip`
- Debugging enabled for development

## Installation

### Prerequisites

Make sure you have the following installed on your local development machine:

- [Python 3.x](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [virtualenv](https://virtualenv.pypa.io/en/latest/)

### Steps to Install

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/GeorgeZeng/MICS_Capstone.git
    cd MICS_Capstone
    ```

2. Create a virtual environment:

    ```bash
    python3 -m venv venv
    ```

3. Activate the virtual environment:

    - On macOS/Linux:

      ```bash
      source venv/bin/activate
      ```

    - On Windows:

      ```bash
      venv\Scripts\activate
      ```

4. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Setup environment file

This application need call API to gather data from other websties:

CriminalIP, AbuseIPDB, Virustotal, ...

1. Sign in and create API key:

    VirusTotal
    * Website: virustotal.com
    * Public API constraints and restrictions
      * The Public API is limited to 500 requests per day and a rate of 4 requests per minute.
      * The Public API must not be used in commercial products or services.
      * The Public API must not be used in business workflows that do not contribute new files.
      * You are not allowed to register multiple accounts to overcome the aforementioned limitations.
    
    CriminalIP
    * Website: criminalip.io
    
    AbuseIPDB
    * Website: abuseipdb.com

    Cloudmersive
    * cloudmersive.com

2. Setup DynamoDB
   
3. Setup Gmail account for sending email

4. Please create a .venv or .env file as below format in the project folder:

    ```bash
    CRIMINALIP_API_KEY = <Your CriminalIP API Key>
    ABUSEIPDB_API_KEY = <Your AubseIPDB API Key>
    VIRUSTOTAL_API_KEY = <Your VirusTotal API Key>
    CLOUDMERSIVE_API_KEY = <Your Cloudmersive API Key>
    aws_access_key_id = <Your DynamoDB Access Key>
    aws_secret_access_key = <Your DynamoDB Secret Access Key>
    MAIL_USERNAME=<Your email username for sending email>
    MAIL_PASSWORD=<Your email password for sending email>
    SECRET_KEY=<Your Secret Key for generating token on unsubscribe URL>
    llm_aws_access_key_id=<AWS keyId of the account>
    llm_aws_secret_access_key=<AWS key secret of the account>
    llm_model_id=<ModelId of the LLM in use.>
    ```
### LLM Model setup
We are using a pre-trained LLM running on AWS bedrock. We are currently using anthropic's claude haiku3, but you can use any model.
Below are the step-by-step instructions to set up the LLM model on AWS bedrock:
1. Go to the AWS bedrock console.
2. Create a user group and add the user to the group. Give the user the necessary permissions to create and use the LLM model.
3. Select the model you want to use. We are using anthropic's claude haiku3.
4. Get the model id.
5. Add the model id, aws keyId and secrets to the .env file as llm_model_id, llm_aws_access_key_id, and llm_aws_secret_access_key respectively.
7. Make sure install boto3 listed in the requirements.txt file.
8. You can now use the LLM model in the application.
9. For the bedrock pricing, please refer to the AWS bedrock pricing page at https://aws.amazon.com/bedrock/pricing/

### Run the application

```bash
python server_flask.py
```

Access application with url: http://localhost:8000/
