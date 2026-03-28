# utils/bruteforce.py

def simple_bruteforce(ip, port):
    """
    Simulated brute-force check (safe demo)
    """

    common_creds = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "1234"),
        ("user", "password")
    ]

    results = []

    for user, pwd in common_creds:
        # Simulated success condition
        if user == "admin" and pwd == "admin":
            results.append(f"Weak credential found → {user}:{pwd}")

    return results