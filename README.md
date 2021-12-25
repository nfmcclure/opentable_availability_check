Check OpenTable site for Availability
==============================

Having problems checking for availability of your favorite restaurant on OpenTable?

All you need is the restaurant ID (in url) and Gmail API tokens.

**Code**

- `src/__main__.py`: This is the main script:

1. It retrieves your Gmail API credentials from `credentials.json`.
You'll need to set this up yourself.

2. Navigate to your favorite restaurant on open table, 
and look in the URL for the restaurant ID. Substitute this in the code.

3. This code checks weekend days (Friday=4, Saturday=5, Sunday=6)
for availabile times. And everytime this script is run, it will
email you the results.


**Deployment**

1. I deployed this on docker w/ AWS Batch + ECR on an AWS-Eventbridge
daily schedule to automate this.  You may do similar.