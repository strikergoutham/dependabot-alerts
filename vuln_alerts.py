import os
import requests
import json
import xlsxwriter
import boto3
import glob

#this script is a bit raw and it serves our purpose. you can modify this script at will.
#update the values here in the script. just lazy to move it to config :D. 
secret_name = "#your_aws_secret_name"
region_name = "#your_aws_region_here"
bucket_name = "#your_aws_bucket_to_output"
repo_owner_name = "#your_github_orgspace_name"
s3 = boto3.client('s3')
s3_delta = boto3.resource('s3')

# Create a Secrets Manager client
session = boto3.session.Session()
client = session.client(service_name='secretsmanager',region_name=region_name)

#set the secret value to the env variable
get_secret_value_response = client.get_secret_value(SecretId=secret_name)
diction=eval(get_secret_value_response['SecretString'])
os.environ["slack_webhook_dependabot"]=diction['slack_webhook_dependabot']
os.environ["gh_token_dependabot"]=diction['gh_token_dependabot']


headers = {"Authorization": "token {}".format(os.environ['gh_token_dependabot'])}
slack_webhook = os.environ["slack_webhook_dependabot"]
repos = open("scan_repos.txt")
slack_headers = {'Content-Type': 'application/json'}
excel_outfile = xlsxwriter.Workbook('/tmp/dependabot_alerts.xlsx')
excel_sheet = excel_outfile.add_worksheet("Dependabot Alerts")
excel_row = 0
excel_column = 0
excel_headers = ["Repository" ,"Dependabot Alert Summary" ,"Description" ,"Created At", "Origin" , "PublishedAt", "Severity", "Ecoystem" , "Package Name", "Manifest FileName", "Vulnerable Requirements", "State","Fixed At","Fixed Reason Comment" , "Dismissed At" , "Dismissed Reason" , "Dismissed By"]
for header in excel_headers:
    excel_sheet.write(excel_row, excel_column, header)
    excel_column = excel_column + 1
    
excel_row = excel_row + 1
excel_column = 0


def run_query(query, variables): 
        request = requests.post('https://api.github.com/graphql', 
        json={'query': query, 'variables':variables}, headers=headers)
        if request.status_code == 200:
            #print(request.content)
            return request.json()['data']
        else:
            raise Exception("Query failed to run by returning code of {}. {}".format(
                    request.status_code, query))
                

def getDependencyAlerts(repo_owner, repo_name):
    query=''' 
            query($repo_owner: String!, $repo_name: String!, $after: String )  { 
                repository(owner: $repo_owner , name: $repo_name ) {
                    vulnerabilityAlerts(first:100, after: $after) {
                        totalCount
                        nodes {
                            id
                            createdAt
                            number
                            state
                            createdAt
                            fixedAt
                            fixReason
                            dismissReason
                            dismissedAt
                            dismisser
                            {
                            email
                            }
                            securityAdvisory{
                            summary
                            description
                            ghsaId
                            identifiers{
                                type
                                value
                            }
                            origin
                            publishedAt
                            severity
                            }
                        
                            
                            securityVulnerability{
                            package{
                                ecosystem
                                name
                            }
                            }
                            
                            
                            vulnerableManifestFilename
                            vulnerableManifestPath
                            vulnerableRequirements
                        }
                        pageInfo{
                            hasNextPage
                            endCursor
                        }
                    }
                }
    }
    '''
    variables={
            "repo_owner":repo_owner,
            "repo_name": repo_name,
            "after": None
            }

    totalCount=None
    alerts=[]
    while True:
        data=  run_query(query, variables)['repository']['vulnerabilityAlerts']
        totalCount=data['totalCount']
        alerts.extend(data['nodes'])
        if data['pageInfo']['hasNextPage']:
            variables["after"]=data['pageInfo']['endCursor']
        else:
            break

    if len(alerts)==totalCount:
        return alerts
    else:
        raise Exception('error in graphql query.')
        
def main():
    
    
    print("getting previous results from S3....")
    list=s3.list_objects(Bucket=bucket_name)
    if 'Contents' in list:
        for key in list['Contents']:
            print(key['Key'])
            filename = "/tmp/" + str(key['Key'])
            s3.download_file(bucket_name, key['Key'], filename)
    else:
        print("No objects returned")  
    print("emptying the bucket...")
    bucket=s3_delta.Bucket(bucket_name)
    bucket.objects.all().delete()
    
    
    global excel_row,excel_column
    print(glob.glob("/tmp/*.json"))
    for repo in repos:
        repo = repo.rstrip()
        alerts_focus ={}
        alerts = getDependencyAlerts(repo_owner_name,repo)
        if len(alerts) > 0:
            for x in alerts:
               
                if str(x['securityAdvisory']['severity']) == "CRITICAL" or str(x['securityAdvisory']['severity']) == "HIGH" or str(x['securityAdvisory']['severity']) == "MEDIUM":
                    excel_row = excel_row + 1
                    excel_column = 0
                    key = str(x['id'])
                    alerts_focus[key] = {}
                    alerts_focus[key] = x
                    excel_data = [repo,x['securityAdvisory']['summary'],"'"+x['securityAdvisory']['description'],x['createdAt'],x['securityAdvisory']['origin'],x['securityAdvisory']['publishedAt'],x['securityAdvisory']['severity'],x['securityVulnerability']['package']['ecosystem'],x['securityVulnerability']['package']['name'],x['vulnerableManifestFilename'],"'"+str(x['vulnerableRequirements']),x['state'],x['fixedAt'],x['fixReason'],x['dismissedAt'],x['dismissReason']]
                    for item in excel_data:
                            excel_sheet.write(excel_row, excel_column, item)
                            excel_column = excel_column + 1
            #print("......................................................")
        if len(alerts_focus) == 0:
            filename = "/tmp/" + repo + "_dependabot.json"
            if os.path.exists(filename):
                os.remove(filename)
                
        if len(alerts_focus) > 0:
            filename = "/tmp/" + repo + "_dependabot.json"
            if os.path.exists(filename):
                with open(filename, 'r') as rfile:
                    exist_res = json.load(rfile)
                #print(type(exist_res))
                #print(type(alerts_focus))
                for key, value in alerts_focus.items():
                    if key not in exist_res:
                        if value['state'] == "OPEN":
                            package_name_delta = value['securityVulnerability']['package']['name']
                            ecosystem = value['securityVulnerability']['package']['ecosystem']
                            description_delta = value['securityAdvisory']['summary']
                            creation_date_delta = str(value['createdAt'])
                            severity_delta = value['securityAdvisory']['severity']
                            state_delta = value['state']
                            print(repo,package_name_delta,ecosystem,description_delta,creation_date_delta,severity_delta,state_delta)
                            Msg1 = "*[+] New Dependabot Alert!*"
                            data = {"text": Msg1}
                            resp = requests.request(method='POST', url=slack_webhook, headers=slack_headers,json=data)
                            Msg2 = "Repository: "+repo+" , Severity: "+ severity_delta + " , Affected Package: " + package_name_delta + " , Ecosystem: "+ecosystem+ " , Created On: "+creation_date_delta + " , Current State: " + state_delta + " , Summary: "+description_delta
                            details = {"text": Msg2}
                            resp = requests.request(method='POST', url=slack_webhook, headers=slack_headers,json=details)
                            
                            
                
            with open(filename, 'w+') as outfile:
                json.dump(alerts_focus, outfile, indent=4)
                dest_fname = repo + "_dependabot.json"
            s3.upload_file(filename,bucket_name,dest_fname)
                
    excel_outfile.close()
    print("writing output to S3...")
    s3.upload_file("/tmp/dependabot_alerts.xlsx",bucket_name,'dependabot_alerts.xlsx')
