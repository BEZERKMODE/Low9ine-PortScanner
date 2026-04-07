from scanner.basic_scans import tcp_connect_scan
from utils.helpers import resolve_target

target = input("Target: ")
ip = resolve_target(target)

for port in range(20, 100):
    result = tcp_connect_scan(ip, port)
    print(result)