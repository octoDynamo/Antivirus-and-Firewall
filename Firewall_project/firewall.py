import socket
import subprocess
import logging
import threading
import os

# Logging configuration
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Blocklist to store blocked IPs dynamically
blocklist = set()

# Function to add an IP to the blocklist and apply iptables rule
def block_ip(ip):
    if ip not in blocklist:
        blocklist.add(ip)
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info(f"Blocked IP: {ip}")
            print(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error blocking IP: {ip} - {e}")
            print(f"Error blocking IP: {ip} - {e}")

# Function to remove an IP from the blocklist and delete iptables rule
def unblock_ip(ip):
    if ip in blocklist:
        blocklist.remove(ip)
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info(f"Unblocked IP: {ip}")
            print(f"Unblocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error unblocking IP: {ip} - {e}")
            print(f"Error unblocking IP: {ip} - {e}")

# Function to dynamically manage blocklist at runtime
def manage_blocklist():
    while True:
        print("\nFirewall Management:")
        print("1. Block an IP")
        print("2. Unblock an IP")
        print("3. Show Blocklist")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            ip_to_block = input("Enter the IP to block: ")
            block_ip(ip_to_block)
        elif choice == "2":
            ip_to_unblock = input("Enter the IP to unblock: ")
            unblock_ip(ip_to_unblock)
        elif choice == "3":
            print("Current Blocklist:")
            for ip in blocklist:
                print(ip)
        elif choice == "4":
            print("Exiting management...")
            break
        else:
            print("Invalid choice, please try again.")

# Function to analyze packet headers (application layer filtering)
def analyze_packet(packet):
    try:
        # Extract IP headers (simplified example)
        src_ip = socket.inet_ntoa(packet[12:16])  # Source IP
        dest_ip = socket.inet_ntoa(packet[16:20])  # Destination IP
        src_port = int.from_bytes(packet[20:22], "big")  # Source port
        dest_port = int.from_bytes(packet[22:24], "big")  # Destination port

        logging.info(f"Packet detected: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
        print(f"Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

        # Block traffic dynamically based on application logic (e.g., block specific ports)
        if src_ip in blocklist:
            logging.warning(f"Blocked traffic from {src_ip}")
            print(f"Blocked traffic from {src_ip}")
        else:
            print(f"Allowed traffic from {src_ip}")
    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")

# Function to monitor network traffic
def monitor_traffic():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        logging.info("Traffic monitoring started...")
        print("Traffic monitoring started...")

        while True:
            packet, addr = sock.recvfrom(65535)  # Capture a packet
            src_ip = addr[0]
            analyze_packet(packet)

            # Block IP dynamically if needed
            if src_ip in blocklist:
                logging.warning(f"Blocked connection from {src_ip}")
                print(f"Blocked connection from {src_ip}")
            else:
                print(f"Allowed connection from {src_ip}")

    except KeyboardInterrupt:
        logging.info("Traffic monitoring stopped.")
        print("\nTraffic monitoring stopped.")
    except Exception as e:
        logging.error(f"Error in monitoring traffic: {e}")
        print(f"Error in monitoring traffic: {e}")

# Main function to start the firewall
if __name__ == "__main__":
    print("Starting enhanced firewall...")
    logging.info("Starting enhanced firewall...")

    # Ensure the script is running with root/admin privileges
    if os.geteuid() != 0:
        print("This script must be run as root.")
        exit()

    # Start the blocklist management in a separate thread
    management_thread = threading.Thread(target=manage_blocklist)
    management_thread.daemon = True
    management_thread.start()

    # Start monitoring network traffic
    monitor_traffic()
