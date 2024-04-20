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
import time
from scapy.all import *
from scapy.contrib.igmp import *
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

    def check_header_ipv4(self, output, frame_length):
        self.assertIn(f"frame length: {frame_length} bytes", output, colored(f"Frame length {frame_length} bytes not found in output.", "red"))
        self.assertIn("src MAC: 00:00:00:00:00:00", output, colored("Src MAC 00:00:00:00:00:00 not found in output.", "red"))
        self.assertIn("dst MAC: ff:ff:ff:ff:ff:ff", output, colored("Dst MAC ff:ff:ff:ff:ff:ff not found in output.", "red"))
        self.assertIn("src IP: 127.0.0.1", output, colored("Src IP 127.0.0.1 not found in output.", "red"))
        self.assertIn("dst IP: 127.0.0.1", output, colored("Dst IP 127.0.0.1 not found in output.", "red"))

    def check_header_ipv6(self, output, frame_length):
        self.assertIn(f"frame length: {frame_length} bytes", output, colored(f"Frame length {frame_length} bytes not found in output.", "red"))
        self.assertIn("src MAC: 00:00:00:00:00:00", output, colored("Src MAC 00:00:00:00:00:00 not found in output.", "red"))
        self.assertIn("dst MAC: ff:ff:ff:ff:ff:ff", output, colored("Dst MAC ff:ff:ff:ff:ff:ff not found in output.", "red"))
        self.assertIn("src IP: ::1", output, colored("Src IP ::1 not found in output.", "red"))
        self.assertIn("dst IP: ::1", output, colored("Dst IP ::1 not found in output.", "red"))

    def send_tcp(self, data):
        packet = IP(dst="127.0.0.1") / TCP(dport=80, sport=20) / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_udp(self, data):
        packet = IP(dst="127.0.0.1") / UDP(dport=53, sport=20) / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_icmp4(self, data):
        packet = IP(dst="127.0.0.1") / ICMP() / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_icmp6(self, data):
        packet = IPv6(dst="::1") / ICMPv6EchoRequest() / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_arp(self, data):
        packet = ARP(pdst="127.0.0.1") / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_ndp(self, data):
        packet = IPv6(dst="::1") / ICMPv6ND_NS() / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_igmp(self, data):
        packet = IP(dst="127.0.0.1") / IGMP() / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def send_mld(self, data):
        packet = IPv6(src="::1", dst="::1") / ICMPv6MLQuery() / data
        send(packet)
        time.sleep(0.1)
        return self.sniffer_process.stdout.read().strip()

    def test_tcp(self):
        args = ["-i", "lo", "--tcp", "--port-destination", "80"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_tcp, args, data)
        self.assertIn("src port: 20", output, colored("Src port 20 not found in output.", "red"))
        self.assertIn("dst port: 80", output, colored("Dst port 80 not found in output.", "red"))
        self.check_header_ipv4(output, 66)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_udp(self):
        args = ["-i", "lo", "--udp", "--port-destination", "53"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_udp, args, data)
        self.assertIn("dst port: 53", output, colored("dst port 53 not found in output.", "red"))
        self.assertIn("src port: 20", output, colored("src port 20 not found in output.", "red"))
        self.check_header_ipv4(output, 54)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_icmp4(self):
        args = ["-i", "lo", "--icmp4"]
        data = "DATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATADATA"
        output = self.run_test_with_timeout(self.send_icmp4, args, data)
        self.check_header_ipv4(output, 210)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_icmp6(self):
        args = ["-i", "lo", "--icmp6"]
        data = "ICMP6heyho"
        output = self.run_test_with_timeout(self.send_icmp6, args, data)
        self.check_header_ipv6(output, 72)
        self.assertInPayload("", output)
        print(colored("Test passed.", "green"))

    def test_arp(self):
        args = ["-i", "lo", "--arp"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_arp, args, data)
        self.check_header_ipv4(output, 42)
        print(colored("Test passed.", "green"))

    def test_ndp(self):
        args = ["-i", "lo", "--ndp"]
        data = "NDPNDPNDPNDPNDPNDPNDPNDPNDPNDPNDPNDP"
        output = self.run_test_with_timeout(self.send_ndp, args, data)
        self.check_header_ipv6(output, 118)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_igmp(self):
        args = ["-i", "lo", "--igmp"]
        data = "igmp"
        output = self.run_test_with_timeout(self.send_igmp, args, data)
        self.check_header_ipv4(output, 46)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_mld(self):
        args = ["-i", "lo", "--mld"]
        data = "MLD_MLD_MLD_MLD"
        output = self.run_test_with_timeout(self.send_mld, args, data)
        self.check_header_ipv6(output, 93)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_mulitple_packets(self):
        args = ["-i", "lo", "-n", "3", "--ndp", "--mld", "--igmp"]
        data = "FirstPacket"
        data2 = "SecondPacket"
        data3 = "ThirdPacket"
        output = self.run_test_with_timeout(self.send_ndp, args, data)
        output2 = self.run_test_with_timeout(self.send_mld, args, data2)
        output3 = self.run_test_with_timeout(self.send_igmp, args, data3)
        self.assertInPayload(data, output)
        self.assertInPayload(data2, output2)
        self.assertInPayload(data3, output3)
        print(colored("Test passed.", "green"))

    def test_tcp_or_udp(self):
        args = ["-i", "lo", "--tcp", "--udp", "--port-source", "20", "-n", "2"]
        data = "FirstPacketTCP"
        data2 = "SecondPacketUDP"
        output = self.run_test_with_timeout(self.send_tcp, args, data)
        output2 = self.run_test_with_timeout(self.send_udp, args, data2)
        self.assertIn("dst port: 80", output, colored("Port 80 not found in output.", "red"))
        self.check_header_ipv4(output, 68)
        self.assertInPayload(data, output)
        self.check_header_ipv4(output2, 57)
        self.assertInPayload(data2, output2)
        print(colored("Test passed.", "green"))

    def test_filter1(self):
        args = ["-i", "lo", "--tcp", "-p", "20"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_tcp, args, data2)
        self.assertIn("src port: 20", output, colored("Port 20 not found in output.", "red"))
        self.assertIn("dst port: 80", output, colored("Port 80 not found in output.", "red"))
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_filter2(self):
        args = ["-i", "lo", "--udp", "-p", "20"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_tcp, args, data1)
        output = self.run_test_with_timeout(self.send_udp, args, data2)
        self.assertIn("src port: 20", output, colored("Port 20 not found in output.", "red"))
        self.assertIn("dst port: 53", output, colored("Port 53 not found in output.", "red"))
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_filter3(self):
        args = ["-i", "lo", "--icmp4", "--icmp6"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_icmp4, args, data2)
        self.check_header_ipv4(output, 48)
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_filter4(self):
        args = ["-i", "lo", "--arp", "--ndp"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_arp, args, data2)
        self.check_header_ipv4(output, 42)
        print(colored("Test passed.", "green"))

    def test_filter5(self):
        args = ["-i", "lo", "--igmp", "--mld"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_igmp, args, data2)
        self.check_header_ipv4(output, 48)
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_filter6(self):
        args = ["-i", "lo", "--tcp", "--udp", "--port-destination", "80"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_tcp, args, data2)
        self.assertIn("dst port: 80", output, colored("Port 80 not found in output.", "red"))
        self.check_header_ipv4(output, 60)
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_filter7(self):
        args = ["-i", "lo", "--icmp4", "--icmp6", "--port-source", "20"]
        data1 = "Hello,World!"
        data2 = "BarFoo"
        self.run_test_with_timeout(self.send_udp, args, data1)
        output = self.run_test_with_timeout(self.send_icmp4, args, data2)
        self.check_header_ipv4(output, 48)
        self.assertInPayload(data2, output)
        print(colored("Test passed.", "green"))

    def test_no_package_with_set_filter(self):
        args = ["-i", "lo", "--port-destination", "54"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_udp, args, data)
        self.assertIn("", output, colored("No packets should be sniffed", "red"))
        print(colored("Test passed.", "green"))

    def test_catch_ndp_with_icmp6_fiter(self):
        args = ["-i", "lo", "--icmp6"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_ndp, args, data)
        self.check_header_ipv6(output, 94)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))

    def test_catch_mld_with_icmp6_fiter(self):
        args = ["-i", "lo", "--icmp6"]
        data = "Hello,World!"
        output = self.run_test_with_timeout(self.send_mld, args, data)
        self.check_header_ipv6(output, 90)
        self.assertInPayload(data, output)
        print(colored("Test passed.", "green"))




if __name__ == "__main__":
    unittest.main()
