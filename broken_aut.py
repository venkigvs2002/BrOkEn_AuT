#!/usr/bin/env python3
#
# BrOkEn_AuT (22-02-2025)
# Written by Venki (@Ganji)
# Please use responsibly...
# Software URL:

import requests
import pyfiglet
from termcolor import colored  # For colored output

def print_banner():
    """Prints a simple ASCII banner."""
    banner = pyfiglet.figlet_format("BrOkEn_AuT")
    print(banner)
    print("by @ganji lvl.1".rjust(len(banner.split("\n")[0])))

def load_urls(file_path):
    """Loads URLs from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file if line.strip()]
        if not urls:
            raise ValueError(f"Error: '{file_path}' is empty. Please provide URLs.")
        return urls
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def get_user_headers(user_count):
    """Prompts user to enter headers for each request."""
    users_headers = []
    for i in range(1, user_count + 1):
        print(f"\nEnter headers for User {i}:")
        headers = {}
        while True:
            key = input(f"User {i} Header Name (or 'done' to finish): ").strip()
            if key.lower() == "done":
                break
            value = input(f"User {i} Header Value: ").strip()
            headers[key] = value
        users_headers.append(headers)
    return users_headers

def format_output(url, status_code):
    """Formats the output with colors based on status codes."""
    color_map = {
        200: "red",
        301: "yellow",
        302: "yellow",
        404: "cyan",
        503: "magenta"
    }
    color = color_map.get(status_code, "white")
    return colored(f"{url} [{status_code}]", color)

def send_requests(urls, users_headers, output_file):
    """Sends HTTP GET requests to each URL with specified headers."""
    if not urls:
        print("No URLs to process. Exiting.")
        return

    with open(output_file, "w", encoding="utf-8") as out:
        print("\n=== Results ===\n")
        for url in urls:
            for i, headers in enumerate(users_headers, 1):
                try:
                    response = requests.get(url, headers=headers, timeout=10)
                    status_code = response.status_code
                    formatted_output = format_output(url, status_code)

                    out.write(f"URL: {url}\nUser {i} Headers: {headers}\nStatus Code: {status_code}\n")

                    if status_code == 200:
                        out.write(f"Response Body:\n{response.text}\n\n")

                    print(formatted_output)

                except requests.exceptions.RequestException as e:
                    error_msg = f"Error with {url} for User {i}: {e}"
                    print(colored(error_msg, "red"))
                    out.write(error_msg + "\n")

if __name__ == "__main__":
    print_banner()  # Print the custom banner

    while True:
        try:
            user_count = int(input("Enter the number of users to test: "))
            if user_count < 1:
                print("Please enter a valid positive number.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a number.")

    users_headers = get_user_headers(user_count)

    urls_file = input("Enter the path of the URLs file: ").strip()
    output_file = input("Enter the path and name of the output file: ").strip()

    urls = load_urls(urls_file)
    send_requests(urls, users_headers, output_file)
