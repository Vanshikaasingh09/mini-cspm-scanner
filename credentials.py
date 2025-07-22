# credentials.py
import boto3

def create_session(aws_access_key, aws_secret_key, aws_region):
    return boto3.session.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
