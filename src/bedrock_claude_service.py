import os
import boto3
import json

def invoke_bedrock_model(IOC, combined_result_json):
    # Convert combined_result_json to a JSON string
    combined_result_json_str = json.dumps(combined_result_json)

    # Configure AWS credentials directly in the client initialization
    prompt = f'Is {IOC} a malicious? Generate a one line brief summary. Use the provided json for inferences, but in the generated summary do not say based on provided information or JSON. Here is the JSON: {combined_result_json_str}'
    client = boto3.client(
        'bedrock-runtime',
        aws_access_key_id=os.getenv("llm_aws_access_key_id"),
        aws_secret_access_key=os.getenv("llm_aws_secret_access_key"),
        region_name='us-west-2'  # Specify your AWS region
    )

    # Define the input payload for the Messages API
    input_payload = {
        'anthropic_version': 'bedrock-2023-05-31',
        "max_tokens": 1024,
        "temperature": 0.5,
        'messages': [
            {'role': 'assistant', 'content': [{'type': 'text', 'text': 'You are a helpful assistant. Do not make any reference to the provided JSON. Make it sound like a human generated summary.'}]},
            {'role': 'user', 'content':  prompt}
        ]
    }

    # Convert the input payload to JSON
    input_payload_json = json.dumps(input_payload)

    # Invoke the model using the Messages API and handle the response
    response = client.invoke_model(
        modelId=os.getenv("llm_model_id"),
        body=input_payload_json
    )
    summary = extract_text_from_json(response['body'].read().decode('utf-8'))
    # Return the response from the model
    return summary

def extract_text_from_json(json_str):
    # Parse the JSON string to a Python dictionary
    data = json.loads(json_str)

    # Extract the text content from the 'content' field
    for item in data.get('content', []):
        if item.get('type') == 'text':
            return item['text']

    return None

