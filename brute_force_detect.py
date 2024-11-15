from scapy.all import sniff,TCP,IP
from collections import Counter, defaultdict
from datetime import datetime, timedelta

attempt_thershould = 5 # number of attempt from a single IP within the timeframe
time_window = timedelta(seconds=60) # timeframe in which attempts are counted

connections_attemps = defaultdict(lambda: defaultdict(list)) # scr ip list with timestamp
alerted_list = set() #track IPs we have already alearted on

def detect_brute_force(packet):
    timestamp = datetime.now()

    # detect SSH brute force attack
    if packet.haslayer('TCP') and packet['TCP'].dport == 22:
        src_ip =packet['IP'].src
        service = "SSH"

        # log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # remove outdated attemps from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip] if timestamp - time < time_window
        ]

        # check if the number of attemps excedes the thershould
        if len(connections_attemps)>=attempt_thershould :
            #only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! form {src_ip}")
                alerted_list.append(src_ip)

    # detect FTP brute force attack
    elif packet.haslayer('TCP') and packet['TCP'].dport == 21:
        src_ip =packet['IP'].src
        service = "FTP"

        # log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # remove outdated attemps from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip] if timestamp - time < time_window
        ]

        # check if the number of attemps excedes the thershould
        if len(connections_attemps)>=attempt_thershould :
            #only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! form {src_ip}")
                alerted_list.append(src_ip)
    
    # detect RDP(remote desktop protocol) brute force attack
    elif packet.haslayer('TCP') and packet['TCP'].dport == 3389:
        src_ip =packet['IP'].src
        service = "RDP"

        # log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # remove outdated attemps from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip] if timestamp - time < time_window
        ]

        # check if the number of attemps excedes the thershould
        if len(connections_attemps)>=attempt_thershould :
            #only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! form {src_ip}")
                alerted_list.append(src_ip)
    
    # detect SMTP brute force attack 
    elif packet.haslayer('TCP') and packet['TCP'].dport == 25:
        src_ip =packet['IP'].src
        service = "SMTP"

        # log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # remove outdated attemps from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip] if timestamp - time < time_window
        ]

        # check if the number of attemps excedes the thershould
        if len(connections_attemps)>=attempt_thershould :
            #only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! form {src_ip}")
                alerted_list.append(src_ip)
    
    # detect HTTP brute force attack
    elif packet.haslayer('TCP') and packet['TCP'].dport == 80:
        src_ip =packet['IP'].src
        service = "HTTP"

        # log the connection attempt
        connections_attemps[service][src_ip].append(timestamp)

        # remove outdated attemps from the log
        connections_attemps[service][src_ip] = [
            time for time in connections_attemps[service][src_ip] if timestamp - time < time_window
        ]

        # check if the number of attemps excedes the thershould
        if len(connections_attemps)>=attempt_thershould :
            #only alert once per IP within the detection period
            if src_ip not in alerted_list:
                print(f"ALERT: Brute force attack detected! form {src_ip}")
                alerted_list.append(src_ip)


print("starting brute force scanning...........")
sniff(filter = "tcp",prn=detect_brute_force,store=0)