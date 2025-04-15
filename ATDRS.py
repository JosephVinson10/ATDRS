import scapy.all as scapy
import smtplib
from email.message import EmailMessage
import time
import threading
from datetime import datetime

# Configuration
SUSPICIOUS_IPS = ["192.168.1.100", "203.0.113.15"]
ALERT_EMAIL = "alert@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your_email@gmail.com"
EMAIL_PASSWORD = "your_password"

# Log File
LOG_FILE = "network_log.txt"
start_time = None
stop_sniffing = False


def write_log(message):
    """Write detailed log message to the log file."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")


def send_email_alert(packet):
    """Send an email alert when suspicious activity is detected."""
    write_log(f"ALERT: Suspicious packet detected from {packet[scapy.IP].src}")
    try:
        msg = EmailMessage()
        msg.set_content(f"Suspicious activity detected:\n\n{packet.summary()}")
        msg["Subject"] = "Security Alert: Suspicious Network Activity"
        msg["From"] = EMAIL_USERNAME
        msg["To"] = ALERT_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
            write_log("ALERT: Email sent successfully.")
    except Exception as e:
        write_log(f"ERROR: Failed to send email - {e}")


def packet_callback(packet):
    """Callback function to analyze each packet and log details."""
    if stop_sniffing:
        return

    write_log("Packet captured")
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        packet_size = len(packet)
        
        explanation = f"Packet from {ip_src} to {ip_dst} using protocol {protocol}, size: {packet_size} bytes."
        write_log(explanation)

        if ip_src in SUSPICIOUS_IPS:
            write_log(f"ALERT: Suspicious packet detected from {ip_src}")
            send_email_alert(packet)


def stop_monitoring():
    """Stop packet sniffing after 30 seconds."""
    global stop_sniffing
    time.sleep(30)
    stop_sniffing = True
    write_log("INFO: Network monitoring stopped after 30 seconds.")


def monitor_network(interface="Intel(R) Wi-Fi 6E AX211 160MHz"):
    """Start network monitoring on the specified interface using its name."""
    global start_time, stop_sniffing
    stop_sniffing = False
    start_time = datetime.now()

    write_log(f"INFO: Starting network monitoring on interface: {interface}")
    print("Monitoring network traffic on interface:", interface)
    try:
        # Start timer in a separate thread
        threading.Thread(target=stop_monitoring, daemon=True).start()

        # Start sniffing packets
        scapy.sniff(iface=interface, store=False, prn=packet_callback, stop_filter=lambda x: stop_sniffing)
    except Exception as e:
        write_log(f"ERROR: {e}")


if __name__ == "__main__":
    print("Starting Automated Threat Detection and Response System (ATDRS)...")
    write_log("INFO: Starting Automated Threat Detection and Response System (ATDRS)...")
    monitor_network("Intel(R) Wi-Fi 6E AX211 160MHz")  # Use Wi-Fi interface by name
    # OR Use Ethernet
    # monitor_network("Realtek PCIe GbE Family Control_")
    write_log("INFO: Network monitoring complete.")
    print("Network monitoring stopped.")
