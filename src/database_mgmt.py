import boto3
from datetime import datetime, timedelta
import os
import uuid
from botocore.exceptions import ClientError
from decimal import Decimal

from dotenv import find_dotenv, load_dotenv

dotenv_path = find_dotenv()

load_dotenv(dotenv_path)

# Got Access Key ID and Secret Access Key from environment variables
access_key = os.getenv("aws_access_key_id")
secret_key = os.getenv("aws_secret_access_key")
region_name = 'us-west-2'  

# Initialize a session using your access keys
session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name=region_name
)

# Create a DynamoDB resource
dynamodb = session.resource('dynamodb')

# Function to convert floats in JSON to Decimal
def convert_floats_to_decimal(data):
    if isinstance(data, list):
        return [convert_floats_to_decimal(item) for item in data]
    elif isinstance(data, dict):
        return {k: convert_floats_to_decimal(v) for k, v in data.items()}
    elif isinstance(data, float):
        return Decimal(str(data))  # Convert float to Decimal
    return data

# Create IOC_Records table
def create_ioc_table():
    table = dynamodb.create_table(
        TableName='ioc_prd',
        KeySchema=[
            {
                'AttributeName': 'ioc_id',  # Primary key (partition key)
                'KeyType': 'HASH'  # HASH = partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'ioc_id',  # Primary key
                'AttributeType': "S"  # Store UUID as a string
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )

    # Wait for the table to be created
    table.wait_until_exists()
    print(f"Table {table.table_name} created successfully.")

def create_subscription_table():
    table = dynamodb.create_table(
        TableName='subscription_prd',
        KeySchema=[
            {
                'AttributeName': 'subscription_id',  # Primary key (partition key)
                'KeyType': 'HASH'  # HASH = partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'subscription_id',  # Primary key
                'AttributeType': "S"  # Store UUID as a string
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )

    # Wait for the table to be created
    table.wait_until_exists()
    print(f"Table {table.table_name} created successfully.")

def insert_or_update_ioc_item(searched_query, ioc_score=0, attributes={}):
    table = dynamodb.Table('ioc_prd')

    create_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Convert all float values in attributes to Decimal
    attributes = convert_floats_to_decimal(attributes)

    # First, check if an item with the given searched_query and subscription_email exists
    response = table.scan(
        FilterExpression="searched_query = :searched_query",
        ExpressionAttributeValues={
            ':searched_query': searched_query,
        }
    )

    if len(response['Items']) == 0:
        # Item doesn't exist, so insert a new one
        ioc_id = str(uuid.uuid4())  # Generate a UUID for ioc_id
        try:
            table.put_item(
                Item={
                    'ioc_id': ioc_id,
                    'searched_query': searched_query,
                    'create_ts': create_ts,
                    'ioc_score': ioc_score,
                    'attributes': attributes
                }
            )
            # print(f"Item inserted successfully with ioc_id {ioc_id}!")

            return True, f'Insert an item for {searched_query} successfully!'
        
        except ClientError as e:

            # print(f"Error occurred during insertion: {e.response['Error']['Message']}")

            return False, "Internal database error occurred during subscribing!"
        
    else:
        # Item exists, so update it
        existing_item = response['Items'][0]  # Get the existing item (assuming it's unique)
        ioc_id = existing_item['ioc_id']
        
        try:
            # Update the existing item
            response = table.update_item(
                Key={'ioc_id': ioc_id},
                UpdateExpression="""
                    SET ioc_score = :ioc_score,
                        create_ts = :create_ts,
                        attributes = :attributes
                """,
                ExpressionAttributeValues={
                    ':ioc_score': ioc_score,
                    ':create_ts': create_ts,
                    ':attributes': attributes
                },
                ReturnValues="UPDATED_NEW"
            )
            # print(f"Item updated: {response['Attributes']}")

            return True, f'Update item for {searched_query} successfully!'
        
        except ClientError as e:
            # print(f"Error occurred during update: {e.response['Error']['Message']}")

            return False, "Internal error occurred during subscribing!"

def insert_or_update_subscription_item(searched_query, subscription_email=None):
    table = dynamodb.Table('subscription_prd')

    create_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    success_ioc, ioc_id = search_ioc_id_by_searched_query(searched_query)

    if not success_ioc:

        return False, "Internal database error occurred during subscribing!"

    # First, check if an item with the given searched_query and subscription_email exists
    response = table.scan(
        FilterExpression="ioc_id = :ioc_id AND subscription_email = :subscription_email",
        ExpressionAttributeValues={
            ':ioc_id': ioc_id,
            ':subscription_email': subscription_email
        }
    )

    if len(response['Items']) == 0:
        # Item doesn't exist, so insert a new one
        subscription_id = str(uuid.uuid4())  # Generate a UUID for ioc_id
        try:
            table.put_item(
                Item={
                    'subscription_id': subscription_id,
                    'ioc_id': ioc_id,
                    'subscription_email': subscription_email,
                    'create_ts': create_ts,
                }
            )
            # print(f"Item inserted successfully with ioc_id {ioc_id}!")

            return True, f'Subscribe {subscription_email} for {searched_query} successfully!'
        
        except ClientError as e:

            # print(f"Error occurred during insertion: {e.response['Error']['Message']}")

            return False, "Internal database error occurred during subscribing!"
        
    else:
        # Item exists, so update it
        existing_item = response['Items'][0]  # Get the existing item (assuming it's unique)
        subscription_id = existing_item['subscription_id']
        
        try:
            # Update the existing item
            response = table.update_item(
                Key={'subscription_id': subscription_id},
                UpdateExpression="""
                    SET create_ts = :create_ts
                """,
                ExpressionAttributeValues={
                    ':create_ts': create_ts
                },
                ReturnValues="UPDATED_NEW"
            )
            # print(f"Item updated: {response['Attributes']}")

            return True, f'You already subscribed {subscription_email} for {searched_query}, refresh for 7 days again!'
        
        except ClientError as e:
            # print(f"Error occurred during update: {e.response['Error']['Message']}")

            return False, "Internal error occurred during subscribing!"

# Function to search ioc_id by searched_query
def search_ioc_id_by_searched_query(searched_query):

    table = dynamodb.Table('ioc_prd')

    try:
        response = table.scan(
            FilterExpression="searched_query = :searched_query",
            ExpressionAttributeValues={
                ':searched_query': searched_query
            }
        )
        items = response.get('Items', [])
        if items:
            return True, items[0]['ioc_id']
        else:
            return False, "No matching ioc_id found for the searched_query."

    except ClientError as e:
        return False, f"Error occurred: {e.response['Error']['Message']}"

# Function to search searched_query by ioc_id
def search_searched_query_by_ioc_id(ioc_id):

    table = dynamodb.Table('ioc_prd')

    try:
        response = table.get_item(Key={'ioc_id': ioc_id})
        item = response.get('Item')
        if item:
            return True, item['searched_query']
        else:
            return False, "No matching searched_query found for the ioc_id."

    except ClientError as e:
        return False, f"Error occurred: {e.response['Error']['Message']}"

# Function to search attributes by ioc_id
def search_attributes_by_ioc_id(ioc_id):

    table = dynamodb.Table('ioc_prd')

    try:
        response = table.get_item(Key={'ioc_id': ioc_id})
        item = response.get('Item')
        if item:
            return True, item['attributes']
        else:
            return False, "No matching attributes found for the ioc_id."

    except ClientError as e:
        return False, f"Error occurred: {e.response['Error']['Message']}"

# Function to scan a table
def fetch_table(table_name):

    table = dynamodb.Table(table_name)
    try:
        response = table.scan()
        records = response.get('Items', [])  # Get all items or an empty list if none
        
        # Handle pagination (if there are more than 1 MB of results)
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            records.extend(response.get('Items', []))
        
        return True, records  # Return success and the records

    except ClientError as e:
        return False, f"Error occurred during scan: {e.response['Error']['Message']}"  # Return error message

# Function to delete records older than notified_days days
def delete_old_records(table_name, notified_days):

    table = dynamodb.Table(table_name)
    # Calculate the timestamp for notified_days days ago
    seven_days_ago = (datetime.now() - timedelta(days=notified_days)).strftime('%Y-%m-%d %H:%M:%S')

    try:
        # Scan for records where create_ts is older than 7 days
        response = table.scan(
            FilterExpression="create_ts < :seven_days_ago",
            ExpressionAttributeValues={
                ':seven_days_ago': seven_days_ago
            }
        )
        items_to_delete = response.get('Items', [])
        
        # Handle pagination if there are more than 1 MB of results
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression="create_ts < :seven_days_ago",
                ExpressionAttributeValues={
                    ':seven_days_ago': seven_days_ago
                },
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items_to_delete.extend(response.get('Items', []))

        # Delete the items
        for item in items_to_delete:
            try:
                table.delete_item(
                    Key={
                        'subscription_id': item['subscription_id']  # 'subscription_id' is the partition key
                    }
                )
                print(f"Deleted item with subscription_id {item['subscription_id']}")
            except ClientError as e:
                print(f"Error deleting item with subscription_id {item['subscription_id']}: {e.response['Error']['Message']}")

        return True, f"{len(items_to_delete)} items deleted that were older than {notified_days} days from table {table_name}."

    except ClientError as e:
        return False, f"Error occurred during scan: {e.response['Error']['Message']}"

# Function to delete records for a specific subscription_email
def delete_records_by_subscription_email(table_name, subscription_email):

    table = dynamodb.Table(table_name)
    try:
        # Scan for records with the matching subscription_email
        response = table.scan(
            FilterExpression="subscription_email = :subscription_email",
            ExpressionAttributeValues={
                ':subscription_email': subscription_email
            }
        )
        items_to_delete = response.get('Items', [])

        # Handle pagination if there are more than 1 MB of results
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression="subscription_email = :subscription_email",
                ExpressionAttributeValues={
                    ':subscription_email': subscription_email
                },
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items_to_delete.extend(response.get('Items', []))

        # Delete the items
        for item in items_to_delete:
            try:
                table.delete_item(
                    Key={
                        'subscription_id': item['subscription_id']  # 'subscription_id' is the partition key
                    }
                )
                print(f"Deleted item with subscription_id {item['subscription_id']}")
            except ClientError as e:
                print(f"Error deleting item with subscription_id {item['subscription_id']}: {e.response['Error']['Message']}")

        return True, f"{len(items_to_delete)} items deleted for subscription_email: {subscription_email}"

    except ClientError as e:
        return False, f"Error occurred during scan: {e.response['Error']['Message']}"

# Function to scan subscription table and retrieve all ioc_id values
def scan_subscription_for_ioc_id():

    table = dynamodb.Table('subscription_prd')

    try:
        response = table.scan(
            ProjectionExpression="ioc_id"  # Only retrieve the ioc_id attribute
        )
        items = response.get('Items', [])
        # Extract all the ioc_id values
        ioc_ids = [item['ioc_id'] for item in items if 'ioc_id' in item]
        return ioc_ids

    except ClientError as e:
        # print(f"Error occurred: {e.response['Error']['Message']}")
        return None

# Example usage
if __name__ == '__main__':

    print("Processing DB")

    # create_ioc_table()

    # create_subscription_table()


    ### test delete old records
    # delete_old_records('subscription_prd', 1)

    ### test delete based on subscription email
    # delete_records_by_subscription_email('subscription_prd', 'gzeng@berkeley.edu')