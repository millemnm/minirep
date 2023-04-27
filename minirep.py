# This an interactive script that gathers information about an IP address from various services

import argparse
import colorama
import json
import os
import requests
from os.path import dirname
from termcolor import colored,cprint

def fetch_vt_reputation(address,config):

    headers = {'x-apikey': config['vt_api_key']}
    response = requests.get(url=f"{config['vt_api_url']}/ip_addresses/{address}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed VT IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return


def render_directions():
    cprint(colored("""
----------------------------
YOU DECIDE WHAT COMES NEXT
----------------------------""","green"))
    print("""
SYNOPSIS
You are working at a small business which is trying to incorporate threat
intelligence information into its security program. One way of doing so is
to gather IP intelligence to prevent connections to known-malicious IPs.
Your security budget is $9.37, all that was left in the petty-cash drawer
after the March birthdays celebration. You need to come up with a script
to pull IP intelligence and incorporate it into your processes. 

DIRECTIONS
- Look through the APIs in the README section and pick one or two that can 
  help you make the right decision.
- Read the API documentation to determine how the data is structured, what
  routes you should query and what parameters need to be passed.
- Determine how you will incorporate the returned data into your decision-
  making process.
- Ultimately, you need to decide whether you want to DROP, ALERT, or PASS
  connections to this device. For the first iteration, you may do this in
  a few different ways:
    1. An interactive prompt that asks you what action you would like to
       perform after displaying relevant data from the APIs you query
    2. Logic that analyzes the returned information and determines an 
       action automatically.
    3. A combination of the previous options.
- Identify the issues with the approaches above.
- Be careful what you block. Check the reputation scores of public DNS
  services like 8.8.8.8 and 1.1.1.1. These are legitimate services, and
  blocking these at your perimeter could be problematic.
- Share your application with the class.

EXAMPLE
Below is an example that queries the VirusTotal IP reputation service.
Consider how you might leverage this data to make a decision. Review
their documentation to determine what goes into a particular score.
Note that only a small subset of what is returned is printed. Feel free
to explore the complete data set returned to aid your decision.
""")
        
    
def main(args):

    colorama.init()

    # If no address was supplied, prompt
    if not args.Address:
        ip_addr = input("Enter the IP address you would like to check: ")
    else:
        ip_addr = args.Address

    # Load config. Print warning and exit if not found
    try:
        config_file_path = os.path.join(dirname(os.path.realpath(__file__)),"minirep.json")
        config = json.load(open(config_file_path))
    except Exception as e:
        print(f"Failed to load config file from {config_file_path}.\r\nException: {e}")
        return

    # Print the directions. Comment this out when you no longer need it
    # render_directions()

    # Query VirusTotal for IP reputation. Feel free to discard this section or use it in a different way
    if vt_rep := fetch_vt_reputation(ip_addr,config):
        cprint(colored("""
----------------------------
VIRUS TOTAL REPUTATION DATA
----------------------------""",'green'))
        print(f"Reputation Score: {vt_rep['data']['attributes']['reputation']}")
        print(f"Harmless Votes: {vt_rep['data']['attributes']['total_votes']['harmless']}")
        print(f"Malicious Votes: {vt_rep['data']['attributes']['total_votes']['malicious']}")


    # Add your code here

    import requests

    # Set up the API endpoint and parameters
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': '933a69cfcbcb72c4e4ad715ee912087230aef1bc1a71dc02458632dcfafe83c8bb66dcca04012d35',
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_addr,
        'maxAgeInDays': '90'
    }

    # Make the API request and retrieve the reputation score
    response = requests.get(url, headers=headers, params=params)
    
    # Check for errors in the API response
    if response.status_code != 200:
        print(f"Error: API returned status code {response.status_code}")
    elif 'data' not in response.json():
        print(f"No data found for IP address {params['ipAddress']}")
    else:
        score = response.json()['data']['abuseConfidenceScore']

        cprint(colored("""
----------------------------
 Abuse IPDB REPUTATION DATA
----------------------------""",'green'))

        # Determine whether to block, alert, or let the IP address pass based on its reputation score
        if score >= 80:
            print(f"IP address {params['ipAddress']} has a high reputation score of {score}. Blocking.")
            # Your blocking code goes here
        elif score >= 60:
            print(f"IP address {params['ipAddress']} has a moderate reputation score of {score}. Alerting.")
            # Your alerting code goes here
        else:
            print(f"IP address {params['ipAddress']} has a low reputation score of {score}. Letting pass.")
            # Your letting-pass code goes here



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--Address", help ="IP address to scan")
    
    args = parser.parse_args()
    main(args)