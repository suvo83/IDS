from SYN_flood_attack import detect_syn_flood

def run_tests():
    print("Running Test Case 1: Normal Traffic")
    detect_syn_flood("192.168.1.1", "SYN", timestamp=1)
    detect_syn_flood("192.168.1.1", "SYN", timestamp=2)
    detect_syn_flood("192.168.1.1", "SYN", timestamp=3)
    detect_syn_flood("192.168.1.1", "SYN", timestamp=8)
    detect_syn_flood("192.168.1.1", "SYN", timestamp=10)

    print("\nRunning Test Case 2: SYN Flood Simulation")
    detect_syn_flood("192.168.1.2", "SYN", timestamp=1)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=2)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=3)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=4)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=5)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=6)

    print("\nRunning Test Case 3: Mixed Traffic")
    detect_syn_flood("192.168.1.1", "SYN", timestamp=1)
    detect_syn_flood("192.168.1.1", "SYN", timestamp=2)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=3)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=4)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=5)
    detect_syn_flood("192.168.1.2", "SYN", timestamp=6)
    detect_syn_flood("192.168.1.3", "SYN", timestamp=1)
    detect_syn_flood("192.168.1.3", "ACK", timestamp=2)
    detect_syn_flood("192.168.1.3", "SYN", timestamp=4)

    print("\nRunning Test Case 4: Edge Case Just Below Threshold")
    detect_syn_flood("192.168.1.4", "SYN", timestamp=1)
    detect_syn_flood("192.168.1.4", "SYN", timestamp=2)
    detect_syn_flood("192.168.1.4", "SYN", timestamp=3)
    detect_syn_flood("192.168.1.4", "SYN", timestamp=4)
    detect_syn_flood("192.168.1.4", "SYN", timestamp=5)

if __name__ == "__main__":
    run_tests()