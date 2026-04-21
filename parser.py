# Open the authentication log file in read mode
log_file = open("auth.log", "r")

# Dictionary to store the number of failed login attempts per IP address
ip_count = {}

# Iterate through each line in the log file
for line in log_file:
    # Check if the line contains a failed SSH login attempt
    if "Failed password" in line:
        # Split the log line into parts (whitespace-separated)
        parts = line.split()

        # Extract the IP address from the log entry
        # NOTE: This index may vary depending on log format
        ip = parts[5]

        # Count occurrences of each IP address
        if ip in ip_count:
            # Increment count if IP already exists in dictionary
            # Multiple failures from same IP may indicate brute-force attempts
            ip_count[ip] += 1
        else:
            # Initialize count for new IP address
            ip_count[ip] = 1

# Close the log file after processing
log_file.close()

# Print summary of failed login attempts per IP
for ip, count in ip_count.items():
    print(ip, "->", count, "failed login attempts")

# Identify and flag suspicious IP addresses
# Threshold can be adjusted based on security policy
for ip, count in ip_count.items():
    if count >= 3:
        print("ALERT: Suspicious IP detected ->", ip)
