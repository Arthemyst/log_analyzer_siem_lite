def analyze_logs(log_file):
    with open(log_file) as f:
        for line in f:
            if 'Failed password' in line:
                print('[!] Brute-force detected:', line.strip())


if __name__ == '__main__':
    analyze_logs('/var/log/auth.log')
