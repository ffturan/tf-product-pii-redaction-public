import os
import json
import boto3
import psycopg2

#
# SET ENVIRONMENT VARIABLES
#
aurora_username = os.environ.get('AURORA_USERNAME_PARAMETER')
aurora_password = os.environ.get('AURORA_PASSWORD_PARAMETER')
aurora_host = os.environ.get('AURORA_HOST_PARAMETER')
aurora_db = os.environ.get('AURORA_DB_PARAMETER')

def get_parameters():
    """Fetch database connection parameters from Parameter Store"""
    ssm_worker = boto3.client('ssm')
    
    # Define the parameters to fetch
    parameters = [
        aurora_username,
        aurora_host,
        aurora_db
    ]
    
    response = ssm_worker.get_parameters(
        Names=parameters,
        WithDecryption=True
    )
    
    # Create a dictionary of parameters
    param_dict = {param['Name']: param['Value'] for param in response['Parameters']}
    
    # Get password from Secrets Manager
    # secret_name = "mysecretname"
    # secrets_client = boto3.client('secretsmanager')
    # secret_response = secrets_client.get_secret_value(SecretId=secret_name)
    # secret = json.loads(secret_response['SecretString'])
    
    #'password': secret['password'],
    credentials = {
        'username': param_dict.get(aurora_username),
        'password': param_dict.get(aurora_password),
        'host': param_dict.get(aurora_host),
        'db': param_dict.get(aurora_db)
    }
    
    return credentials

def execute_query(connection, query):
    """Execute SQL query and return results"""
    try:
        cursor = connection.cursor()
        cursor.execute(query)
        
        # For SELECT queries
        if cursor.description:
            results = cursor.fetchall()
        else:
            results = "Query executed successfully"
            
        connection.commit()
        return results
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()

def lambda_handler(event, context):
    try:
        # Get database credentials and connection info
        credentials = get_parameters()
        
        # Establish database connection
        connection = psycopg2.connect(
            user=credentials['username'],
            password=credentials['password'],
            host=credentials['host'],
            database=credentials['db']
        )
        
        # Example query - replace with your SQL
        query = "SELECT version()"
        results = execute_query(connection, query)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Query executed successfully',
                'results': str(results)
            })
        }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
    finally:
        if 'connection' in locals():
            connection.close()
