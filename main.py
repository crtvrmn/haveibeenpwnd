#!/usr/bin/env python3
import hashlib
import urllib.request
import sys


def check_if_password_pwned(password):
    sha1sum = create_sha(password)
    sha1_sum_head = sha1sum[:5]
    sha1_sum_tail = sha1sum[5:]
    url = f"https://api.pwnedpasswords.com/range/{sha1_sum_head}"
    response = urllib.request.urlopen(url)
    response_text = response.read().decode()
    print("\n")
    if sha1_sum_tail in response_text:
        count = response_text.split(sha1_sum_tail + ":")[1].split("\r\n")[0]
        print(
            f"❌ '{password}' has been breached! 🚩 (SHA1SUM: {sha1sum}) found in the database {count} times. 🤯"
        )
    else:
        print(f"✅ '{password}' has NOT been breached.")
    print("\n")


def create_sha(input):
    sha1 = hashlib.sha1()
    string = str(input)
    sha1.update(string.encode("utf-8"))
    sha1sum = sha1.hexdigest().upper()
    return sha1sum


def multi_check_loop():
    loop = True
    while loop:
        password = input("Enter password to check: ")
        check_if_password_pwned(password)


def main():
    """
    This Python script is designed to check the security of passwords by comparing their SHA-1 hashes with a database of known breached passwords.
    Append the password you want to check (eg. ./programm.py mypassword) when starting or enter it at runtime
    """
    if len(sys.argv) > 1:
        password = sys.argv[1]
        check_if_password_pwned(password)
    else:
        multi_check_loop()


if __name__ == "__main__":
    main()
