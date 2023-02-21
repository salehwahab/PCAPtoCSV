import csv
import subprocess

# assign the path to your pcap file
pcap_file = "/content/drive/MyDrive/AmcrestCamRTSP_1.pcap"

# Define a function to run the Tshark command and return the output
def run_tshark_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8'), stderr.decode('utf-8')

# Define a function to extract features from the pcap file using Tshark
def extract_features(pcap_file):
    # Define features
    command = ["tshark", "-r", pcap_file, "-T", "fields",
               "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
               "-e", "ip.id", "-e", "ip.flags", "-e", "ip.flags.df",
               "-e", "ip.ttl", "-e", "ip.proto", "-e", "ip.checksum",
               "-e", "ip.len", "-e", "tcp.srcport", "-e", "tcp.dstport",
               "-e", "tcp.seq", "-e", "tcp.ack", "-e", "tcp.stream",
               "-e", "tcp.len", "-e", "tcp.hdr_len", "-e", "tcp.analysis.ack_rtt",
               "-e", "tcp.flags.fin", "-e", "tcp.flags.syn", "-e", "tcp.flags.push",
               "-e", "tcp.flags.ack", "-e", "tcp.window_size", "-e", "tcp.checksum",
               "-e", "frame.time_relative", "-e", "frame.time_delta", "-e", "tcp.time_relative",
               "-e", "tcp.time_delta"]
    
    # Run the Tshark command and capture the output
    stdout, stderr = run_tshark_command(command)
    
    # Split the output into lines and remove any empty lines
    lines = stdout.split('\n')
    lines = [line for line in lines if line.strip()]
    
    # Convert the output into a list of dictionaries, where each dictionary represents a single packet
    features = []
    for line in lines:
        values = line.split('\t')
        feature_dict = {
            "ip.src": values[0],
            "ip.dst": values[1],
            "_ws.col.Protocol": values[2],
            "ip.id": values[3],
            "ip.flags": values[4],
            "ip.flags.df": values[5],
            "ip.ttl": values[6],
            "ip.proto": values[7],
            "ip.checksum": values[8],
            "ip.len": values[9],
            "tcp.srcport": values[10],
            "tcp.dstport": values[11],
            "tcp.seq": values[12],
            "tcp.ack": values[13],
            "tcp.stream": values[14],
            "tcp.len": values[15],
            "tcp.hdr_len": values[16],
            "tcp.analysis.ack_rtt": values[17],
            "tcp.flags.fin": values[18],
            "tcp.flags.syn": values[19],
            "tcp.flags.push": values[20],
            "tcp.flags.ack": values[21],
            "tcp.window_size": values[22],
            "tcp.checksum": values[23],
            "frame.time_relative": values[24],
            "frame.time_delta": values[25],
            "tcp.time_relative": values[26],
        }
        features.append(feature_dict)
    
    return features

# Call the extract_features() function with the pcap file path as the argument
features = extract_features(pcap_file)

# Write the extracted features to a CSV file
csv_file = "extracted_features.csv"
with open(csv_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=features[0].keys())
    writer.writeheader()
    for feature in features:
        writer.writerow(feature)

print(f"Extracted features have been written to {csv_file}")
