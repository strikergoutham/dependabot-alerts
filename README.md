# dependabot-alerts
This script fetches new dependabot SCA alerts(high, critical , medium) and pushes the new open alerts to specified slack channel and writes individual and aggregate output to specified S3 bucket.
Credits to base script which was already available at @ 

#How to :

1. Runs on python 3 runtime .
##this script is written so that it can be deployed as a lambda function.
host the files.

2. Create a lambda function with access to read/write to an output S3 bucket.
3. Create an AWS secret inside secrets manager service with the follwing name value pairs :
            slack_webhook_dependabot : webhook to your slack channel. 
            gh_token_dependabot : github token to read the private repositories.
4. Attach role to Lambda function to read the above created AWS secret.
5. Attach the type of trigger for lambda function set to cron to run daily .(Eventbridge)

6. download the following requirement libraries for python 3 and upload the dependencies to the lambda root:
certifi
charset_normalizer
idna
requests
urllib3

7. Upload all the files in this repo to the lambda root.
8. Edit the file "vuln_alerts.py" for the fields with relavent values : 
        secret_name = "#your_aws_secret_name"
        region_name = "#your_aws_region_here"
        bucket_name = "#your_aws_bucket_to_output"
        repo_owner_name = "#your_github_orgspace_name"
9. Edit file "scan_repos.txt" with repository names(each per line) with dependabot alerts enabled and to monitor for delta alerts.
        
9. Thats it, deploy the lambda function , script should write results to S3 bucket as per the execution and push new dependabot alerts to the desired slack channel daily.
