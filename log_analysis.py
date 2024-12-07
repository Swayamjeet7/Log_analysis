# Import required modules
import re
import pandas as pd

# ANSI color codes
RED = "\033[31m"
GREEN = "\033[32m"
TINT = "\033[38;2;255;182;193m"
RESET = "\033[0m"

# Function to color a column
def color(row):
    return f"{TINT}{row}{RESET}" 

# Function to count the number of accesses for each endpoint in the logs
def accesspoint(endpoints, logs):
    accessed_no = []  # List to store the access count for each endpoint

    # Loop through each endpoint and count occurrences in the logs
    for endpoint in endpoints:
        accessed_no.append(len(re.findall(fr"\s{re.escape(endpoint)}\b", logs)))

    # Create a DataFrame to organize endpoints and their access counts
    df2 = pd.DataFrame({
        "Endpoint": endpoints,
        "Access Count": accessed_no
    })
    
    return df2

# Function to count failed login attempts for a specific IP address
def invalid_cred(ip):

    failed_attempts = 0  # Counter for failed login attempts

    # Read the log file line by line
    for i, line in enumerate(open('sample.log')):
        # Check if the line contains the given IP and the "Invalid credentials" or 401 error message
        
        if re.findall(fr"\b{re.escape(ip)}\b", line) and re.findall(r"Invalid credentials", line):
            failed_attempts += 1  # Increment the counter if both conditions are met
    
    return failed_attempts

# Function to analyze requests and failed login attempts for a list of IP addresses
def finding_requests(ip_addresses, logs):

    requests = []  # List to store request counts for each IP
    failed_attempts = []  # List to store failed login attempts for each IP

    # Loop through each IP address and collect metrics
    for ip in ip_addresses:
        # Count total requests from an IP
        requests.append(len(re.findall(fr"\b{re.escape(ip)}\b", logs)))

        # Count failed login attempts from this IP
        failed_attempts.append(invalid_cred(ip))

    # Create DataFrames for requests and failed login attempts
    df1 = pd.DataFrame({
        "IP Address": ip_addresses,
        "Request Count": requests
    })

    df2 = pd.DataFrame({
        "IP Address": ip_addresses,
        "Failed Login Attempts": failed_attempts
    })

    return df1, df2

# Main function to perform the log analysis
def main():

    # Read the entire log file content into a single string
    with open('sample.log', 'r') as file:
        logs = file.read()

    # Extract all unique IP addresses from the logs using regex
    ip_addresses = [] # List to store the IP addresses
    ip_addresses += re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", logs)
    ip_addresses = list(set(ip_addresses))  # Remove duplicates

    # Extract all unique endpoints accessed using regex
    endpoints = [] # List to store the endpoints
    endpoints += re.findall(r"(?:POST|GET) (/\S+)", logs)
    endpoints = list(set(endpoints))  # Remove duplicates

    # Get request and failed login attempt statistics for each IP address
    df1, df2 = finding_requests(ip_addresses, logs)

    # Get access statistics for each endpoint
    df3 = accesspoint(endpoints, logs)

    # Sort request data
    requests_table = df1.sort_values(by="Request Count", ascending=False)
    # Add colors to column
    # requests_table["Request Count"] = requests_table["Request Count"].apply(color)
    # Remove indices and display
    print(requests_table.to_string(index=False), "\n")

    # Sort endpoint access data
    endpoint_table = df3.sort_values(by="Access Count", ascending=False)

    # Identify the most frequently accessed endpoint
    max_id = endpoint_table["Access Count"].idxmax()
    print("Most Frequently Accessed Endpoint:")
    print(f"{endpoint_table.loc[max_id, 'Endpoint']} (Accessed {TINT}{endpoint_table.loc[max_id, 'Access Count']}{RESET} {GREEN}times{RESET})\n")

    # Identify IPs with significant failed login attempts (default: >10)
    attempts_table = df2[df2["Failed Login Attempts"] > 10]

    # Sort failed attempts data
    attempts_table = attempts_table.sort_values(by="Failed Login Attempts", ascending=False)

    # Display findings on suspicious activity
    if attempts_table.empty:
        print(f"Suspicious Activity {GREEN}Not Detected{RESET}.") # Print if dataframe is empty
    else:
        print(f"Suspicious Activity {RED}Detected{RESET}:") # Print if dataframe is not empty 
        print(attempts_table.to_string(index = False), "\n")

    # Combine all analyzed data into a single dataframe
    table = pd.concat([requests_table, endpoint_table, attempts_table], ignore_index=True)
    # Save it to a CSV file
    table.to_csv("log_analysis_results.csv", index=False)

# Entry point of the script
if __name__ == "__main__":
    main()
