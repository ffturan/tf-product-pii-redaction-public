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
        ssm = boto3.client('ssm')
        respone = ssm.get_parameter(Name=aurora_username, WithDecryption=True)
        db_username = respone['Parameter']['Value']
        # Debug
        # print(db_username)
        respone = ssm.get_parameter(Name=aurora_password, WithDecryption=True)
        db_password = respone['Parameter']['Value']
        # Debug
        # print(db_password)
        respone = ssm.get_parameter(Name=aurora_host, WithDecryption=True)
        db_host = respone['Parameter']['Value']
        # Debug
        # print(db_host)
        respone = ssm.get_parameter(Name=aurora_db, WithDecryption=True)
        db_db = respone['Parameter']['Value']
        # Debug
        # print(db_db)
        
        # Establish database connection
        connection = psycopg2.connect(
            user=db_username,
            password=db_password,
            host=db_host,
            database=db_db
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
