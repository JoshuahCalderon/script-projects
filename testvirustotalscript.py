import requests

# Ask the user for their API key
api_key = input("Please enter your VirusTotal API key: ")

# Ask the user for multiple domain URLs, separated by commas
domains_input = input("Please enter the domains you want to check, separated by commas: ")

# Split the input string into a list of domains
domains = [domain.strip() for domain in domains_input.split(",")]

# Loop through each domain and make the request to VirusTotal
for domain in domains:
    # Construct the URL with the provided domain
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    # Add the API key to the headers for authorization
    headers = {
        "accept": "application/json",
        "x-apikey": api_key  # Include the API key in the request headers
    }

    # Send the GET request to VirusTotal API
    response = requests.get(url, headers=headers)

    # Print the response for each domain
    print(f"\nResults for domain: {domain}")
    if response.status_code == 200:
        print("Response received:")
        print(response.json())  # Print the JSON response
    else:
        print(f"Failed to retrieve data for {domain}. Status code: {response.status_code}")
        print(response.text)
