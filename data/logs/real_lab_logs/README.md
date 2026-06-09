# Real Lab Logs

These logs are sanitized controlled-lab artifacts generated from local PCAP replay and PCAP parsing commands. They demonstrate executable integration with lab-captured logs, not enterprise production telemetry.

- `snort_alert_fast.log`: Snort alert output captured by replaying generated PCAPs through Snort 3.
- `http_access.log`: HTTP/access-style and firewall-style lines parsed from controlled lab PCAP payloads.
- `ssh_auth.log`: SSH auth-style summary derived from SSH lab PCAP payload counts.
- `dns_lab.log`: DNS query log line parsed from the DNS tunneling lab PCAP.
- `icmp_lab.log`: ICMP sweep summary parsed from ICMP lab packets.
- `real_lab_logs_index.csv`: normalized index used by `scripts/run_real_log_integration_eval.py`.
