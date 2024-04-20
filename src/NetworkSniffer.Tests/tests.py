# Michal Balogh, xbalog06
# IPK - project 2
# VUT FIT
# 2024


import sys

debug_mode = "-d" in sys.argv
help = "-h" in sys.argv

if debug_mode:
    sys.argv.remove("-d")

if help:
    print("Usage: python3 tests.py [-d] [-h]")
    print("  -d: debug mode")
    print("  -h: help")
    sys.exit(0)

import sys
import unittest
import re
import subprocess
import os
import time
from scapy.all import *
from termcolor import colored
import threading

path_to_sniffer = "../../ipk-sniffer"

class TestIPKSniffer(unittest.TestCase):
    TIMEOUT = 2

    def setUp(self):
        print()
        print("========================================================================")
        print(colored(f"{self._testMethodName}:", "blue"))

    def tearDown(self):
        print("========================================================================")
        self.stop_sniffer_process()
        super().tearDown()

    @classmethod
    def start_sniffer_process(cls, args):
        cls.sniffer_process = subprocess.Popen([path_to_sniffer] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        time.sleep(1)

    @classmethod
    def stop_sniffer_process(cls):
        cls.sniffer_process.terminate()
        cls.sniffer_process.wait()
        cls.sniffer_process.stdout.close()
        cls.sniffer_process.stderr.close()

    def assertInPayload(self, data, output):
        output = re.sub(r"\b0x[0-9a-f]+:\s(?:[0-9a-f]{2}\s?)+", "", output, flags=re.MULTILINE)
        matches = re.findall(r"^(.+?)$", output, re.MULTILINE)
        ascii_section = "".join(matches).replace("\n", "").strip()
        ascii_section = "".join(matches).replace(" ", "").strip()
        ascii_section = re.sub(r"[^\x20-\x7E]", "", ascii_section)
        self.assertIn(data, ascii_section, colored("Payload not found in output.", "red"))

    def run_test_with_timeout(self, test_method, args, data, timeout=TIMEOUT):
        self.start_sniffer_process(args)

        test_result = None
        def run_and_set_result():
            nonlocal test_result
            try:
                test_result = test_method(data)
            except Exception as e:
                print(colored(f"Test failed: {e}", "red"))
                test_result = e

        test_thread = threading.Thread(target=run_and_set_result)
        test_thread.start()
        test_thread.join(timeout)

        if test_thread.is_alive():
            self.stop_sniffer_process()

        if isinstance(test_result, Exception):
            raise test_result

        if debug_mode:
            print(colored(test_result, "blue"))

        return test_result

    def send_tcp(self, data):
        packet = IP(dst="127.0.0.1") / TCP(dport=80) / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_udp(self, data):
        packet = IP(dst="127.0.0.1") / UDP(dport=53) / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def test_tcp(self):
        args = ["-i", "lo", "--port-destination", "80"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_tcp, args, data)
        self.assertIn("dst port: 80", output, colored("Port 80 not found in output.", "red"))
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_udp(self):
        args = ["-i", "lo", "--port-destination", "53"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_udp, args, data)
        self.assertIn("dst port: 53", output, colored("Port 53 not found in output.", "red"))
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_filter1(self):
        args = ["-i", "lo", "--tcp", "--port-destination", "80"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_tcp, args, data2)
        self.assertIn("dst port: 80", output, colored("Port 80 not found in output.", "red"))
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))


    def test_no_package_with_set_filter(self):
        args = ["-i", "lo", "--port-destination", "54"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_udp, args, data)
        self.assertIn("", output, colored("No packets should be sniffed", "red"))
        print(colored("Test passed.", "green"))



if __name__ == "__main__":
    unittest.main()
