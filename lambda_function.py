import json
import boto3
import os
import base64
import vuln_alerts as v


    
def lambda_handler(event, context):
    
    v.main()
    
    return "sucess"
