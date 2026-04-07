from utils.helpers import make_result


def raw_scan_not_available(target_ip: str, port: int, timeout: float = 1.0, requested_scan: str = "Raw Scan"):
    return make_result(
        port=port,
        protocol="TCP",
        scan_type=requested_scan,
        state="Unavailable",
        banner="Not implemented in this safe portfolio build."
    )