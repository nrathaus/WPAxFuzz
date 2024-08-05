#!/usr/bin/python

import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

import scapy.all
import scapy.layers.dot11

sys.path.append("src/")
import graphs
import saee
from message_colors import bcolors


def signal_handler(signum, frame):
    """Signal Handler"""
    if signum == signal.SIGUSR2:
        while toStop == 1:
            pass
        print(
            f"\n\n{bcolors.OKBLUE}STA is online{bcolors.ENDC}\n....Resuming execution...."
        )
        time.sleep(1)
    else:
        pass


signal.signal(signal.SIGUSR2, signal_handler)


global deauth_to_send_stop
deauth_to_send_stop = 0


class deauth_Monitor(threading.Thread):
    def run(self):
        """Run"""
        print("Started deauth monitoring!")
        scapy.all.sniff(
            iface=infos.ATTACKING_INTERFACE,
            store=0,
            stop_filter=self.stop_filter,
            filter="(ether dst "
            + infos.STA_MAC
            + " and ether src "
            + infos.AP_MAC
            + ") or (ether dst "
            + infos.AP_MAC
            + " and ether src "
            + infos.STA_MAC
            + ")",
        )

    def stop_filter(self, packet):
        """Stop Filter"""
        global deauth_to_send_stop
        keyword = "Deauthentification"
        if stop_all_threads == 1:
            return True

        if (
            packet.haslayer(scapy.layers.dot11.Dot11Deauth)
            or keyword in packet.summary()
        ):
            print(bcolors.FAIL + "\nFound Deauthentication frame" + bcolors.ENDC)
            time_found = datetime.now().strftime("%H:%M:%S")
            subprocess.call(
                [
                    "echo ",
                    f"{time_found}. Found deauth from {packet[scapy.layers.dot11.Dot11].addr2} "
                    f"to {packet[scapy.layers.dot11.Dot11].addr1} >> {deauth_path} during: {state.message}",
                ],
                shell=True,
            )
            deauth_to_send_stop = 1

            return False

        if packet.haslayer(scapy.layers.dot11.Dot11Disas):
            print(f"{bcolors.FAIL}\nFound Disassociation frame{bcolors.ENDC}")
            time_found = datetime.now().strftime("%H:%M:%S")
            subprocess.call(
                [
                    "echo"
                    f"{time_found}. Found disas from {packet[scapy.layers.dot11.Dot11].addr2} to "
                    f"{packet[scapy.layers.dot11.Dot11].addr1} >> {deauth_path} during: {state.message}",
                ],
                shell=True,
            )
            deauth_to_send_stop = 1
            return False

        return False


class Generate_Frames:
    """Generate Frames"""

    def __init__(
        self,
        ap_mac,
        ap_channel,
        ap_mac_different,
        channel_different,
        sta_mac,
        attacking_interface,
        monitoring_interface,
        password,
    ):
        self.AP_MAC = ap_mac
        self.AP_CHANNEL = ap_channel
        self.AP_MAC_DIFFERENT = ap_mac_different
        self.CHANNEL_DIFFERENT = channel_different
        self.STA_MAC = sta_mac
        self.ATTACKING_INTERFACE = attacking_interface
        self.MONITORING_INTERFACE = monitoring_interface
        self.PASSWORD = password

    def generate_authbody(self, auth_Algorithm, sequence_Number, status1):
        """Generate Authbody"""
        auth_body = (
            scapy.layers.dot11.RadioTap()
            / scapy.layers.dot11.Dot11(
                type=0,
                subtype=11,
                addr1=self.AP_MAC,
                addr2=self.STA_MAC,
                addr3=self.AP_MAC,
            )
            / scapy.layers.dot11.Dot11Auth(
                algo=auth_Algorithm, seqnum=sequence_Number, status=status1
            )
        )
        return auth_body

    def generate_valid_commit_authbody(self):
        """Generate valid Commit Authbody"""
        auth_body = self.generate_authbody(3, 1, 0)
        return auth_body

    def generate_valid_confirm_authbody(self):
        """generate_valid_confirm_authbody"""
        auth_body = self.generate_authbody(3, 2, 0)
        return auth_body

    def generate_group(self):
        """generate_group"""
        group = "\x13\x00"
        return group

    def generate_send_confirm(self, valid):
        """generate_send_confirm"""
        if valid == 0:
            send = "\x00\x00"
        if valid == 1:
            send = "\x00\x02"
        return send

    def generate_payload_confirm(self):
        """generate_payload_confirm"""
        confirm = "something"
        return confirm

    def generate_custom_commit(self, auth, seq, stat):
        """generate_custom_commit"""
        body = self.generate_authbody(auth, seq, stat)
        group = self.generate_group()
        print(f"{infos.STA_MAC.upper()} -> {infos.AP_MAC.upper()}")
        scalar, finite = saee.generate_scalar_finite(
            infos.PASSWORD, infos.STA_MAC.upper(), infos.AP_MAC.upper()
        )
        frame = body / group / scalar / finite
        return frame

    def generate_custom_confirm(self, auth, seq, stat, valid):
        """generate_custom_confirm"""
        body = self.generate_authbody(auth, seq, stat)
        send = self.generate_send_confirm(valid)
        confirm = self.generate_payload_confirm()
        frame = body / send / confirm
        return frame

    def generate_correct_commit(self):
        """generate_correct_commit"""
        auth_body = self.generate_valid_commit_authbody()
        group = self.generate_group()
        scalar, finite = saee.generate_scalar_finite(
            infos.PASSWORD, infos.STA_MAC, infos.AP_MAC
        )
        frame = auth_body / group / scalar / finite
        return frame

    def send_frame(self, frame, burst_number):
        """send_frame"""
        scapy.all.sendp(
            frame, count=burst_number, iface=self.ATTACKING_INTERFACE, verbose=0
        )

    def change_to_diff_frequency(self):
        """Change to Diff Frequency"""
        temp_Mac = self.AP_MAC
        self.AP_MAC = self.AP_MAC_DIFFERENT
        self.AP_MAC_DIFFERENT = temp_Mac

        temp_Channel = self.AP_CHANNEL
        self.AP_CHANNEL = self.CHANNEL_DIFFERENT
        self.CHANNEL_DIFFERENT = temp_Channel

        subprocess.call(
            [f"iwconfig {self.ATTACKING_INTERFACE} channel {self.AP_CHANNEL}"],
            shell=True,
        )
        current_channel = subprocess.check_output(
            [f'iw {self.ATTACKING_INTERFACE} info | grep channel | cut -d " " -f2'],
            shell=True,
        )

        print(
            "\nAP_MAC changed to: "
            + self.AP_MAC
            + "\nChannel changed to: "
            + current_channel
        )

    def to_string(self):
        """To String"""
        print(f"AP_MAC: {self.AP_MAC}")
        print(f"AP_CHANNEL: {self.AP_CHANNEL}")
        print(f"AP_MAC_DIFFERENT: {self.AP_MAC_DIFFERENT}")
        print(f"CHANNEL_DIFFERENT: {self.CHANNEL_DIFFERENT}")
        print(f"STA_MAC: {self.STA_MAC}")
        print(f"ATTACKING_INTERFACE: {self.ATTACKING_INTERFACE}")
        print(f"MONITORING_INTERFACE: {self.MONITORING_INTERFACE}")


class SaveState:
    """SaveState"""

    def __init__(self):
        self.order_values = []
        self.dc_values = []
        self.frames_to_send = 1
        self.auth_values_to_try = 0
        self.sequence_values_to_try = 1
        self.status_values_to_try = 0
        self.identifier = 0
        self.message = "sth"

    def set_values(
        self,
        frames_to_send,
        auth_values_to_try,
        sequence_values_to_try,
        status_values_to_try,
        identifier,
    ):
        """Set Values"""
        self.frames_to_send = frames_to_send
        self.auth_values_to_try = auth_values_to_try
        self.sequence_values_to_try = sequence_values_to_try
        self.status_values_to_try = status_values_to_try
        self.identifier = identifier

    def __eq__(self, other):
        return self.message == other.message

    def append_order(self, list_item):
        """Append Order"""
        found = 0
        if not self.order_values:
            self.order_values.append(list_item)
        else:
            for a in self.order_values:
                if (
                    a[0] == list_item[0]
                    and a[1] == list_item[1]
                    and a[2] == list_item[2]
                ):
                    found = 1
            if found == 0:
                self.order_values.append(list_item)

    def append_cc(self, list_item):
        """Append DC"""
        found = 0
        if not self.dc_values:
            self.dc_values.append(list_item)
        else:
            for a in self.dc_values:
                if (
                    a[0] == list_item[0]
                    and a[1] == list_item[1]
                    and a[2] == list_item[2]
                ):
                    found = 1
                    break

            if found == 0:
                self.dc_values.append(list_item)


class Fuzz:
    """Fuzz"""

    def __init__(self):
        self.total_frames_to_send = 50

        self.auth_values_to_try = [0, 1, 2, 3, 200]
        self.sequence_values_to_try = [1, 2, 3, 4, 200]
        self.status_values_to_try = [0, 1, 200]

    def construct_and_send(self, identifier, burst_number):
        """Construct and Send"""
        time.sleep(0.01)

        for auth_value in self.auth_values_to_try:
            for sequence_value in self.sequence_values_to_try:
                for status_value in self.status_values_to_try:
                    state.set_values(
                        self.total_frames_to_send,
                        auth_value,
                        sequence_value,
                        status_value,
                        identifier,
                    )

                    self.send_packet(
                        auth_value,
                        sequence_value,
                        status_value,
                        identifier,
                        burst_number,
                    )

    def construct_and_send_2(self, identifier):
        """Construct and Send2"""
        time.sleep(10)
        for a in state.order_values:
            auth_valuee = a[0]
            state.auth_values_to_try = auth_valuee

            sequence_valuee = a[1]
            state.sequence_values_to_try = sequence_valuee

            status_value = a[2]
            state.status_values_to_try = status_value

            self.send_packet(
                auth_valuee, sequence_valuee, status_value, identifier, 128
            )

    def fuzz_empty_bodies(self, burst_number):
        """fuzz_empty_bodies"""
        self.construct_and_send(1, burst_number)

    def fuzz_valid_commit_empty_bodies(self, burst_number):
        """fuzz_valid_commit_empty_bodies"""
        self.construct_and_send(2, burst_number)

    def fuzz_valid_commit_good_confirm(self, burst_number):
        """fuzz_valid_commit_good_confirm"""
        self.construct_and_send(3, burst_number)

    def fuzz_valid_commit_bad_confirm(self, burst_number):
        """fuzz_valid_commit_bad_confirm"""
        self.construct_and_send(4, burst_number)

    def fuzz_commit(self, burst_number):
        """fuzz_commit"""
        self.construct_and_send(5, burst_number)

    def fuzz_good_confirm(self, burst_number):
        """fuzz_good_confirm"""
        self.construct_and_send(6, burst_number)

    def fuzz_bad_confirm(self, burst_number):
        """fuzz_bad_confirm"""
        self.construct_and_send(7, burst_number)

    def cyrcle1(self):
        """cyrcle1"""
        self.fuzz_empty_bodies(1)
        self.fuzz_valid_commit_empty_bodies(1)
        self.fuzz_valid_commit_good_confirm(1)
        self.fuzz_valid_commit_bad_confirm(1)
        self.fuzz_commit(1)
        self.fuzz_good_confirm(1)
        self.fuzz_bad_confirm(1)

    def cyrcle2(self):
        """cyrcle2"""
        time.sleep(1)
        self.cyrcle1()

    def cyrcle3(self):
        """cyrcle3"""
        time.sleep(1)
        self.construct_and_send_2(1)
        self.construct_and_send_2(2)
        self.construct_and_send_2(3)
        self.construct_and_send_2(4)
        self.construct_and_send_2(5)
        self.construct_and_send_2(6)
        self.construct_and_send_2(7)

        time.sleep(1)

    def cyrcle4(self):
        """cyrcle4"""
        self.cyrcle3()

    def initiate_fuzzing_logical_mode(self):
        """initiate_fuzzing_logical_mode"""
        self.cyrcle1()
        if CHANNEL_DIFFERENT_FREQUENCY != "00":
            infos.change_to_diff_frequency()
            self.cyrcle2()
            infos.change_to_diff_frequency()

        self.cyrcle3()

        if CHANNEL_DIFFERENT_FREQUENCY != "00":
            infos.change_to_diff_frequency()
            self.cyrcle4()
            infos.change_to_diff_frequency()

    def initiate_fuzzing_extensive_mode(self):
        """initiate_fuzzing_extensive_mode"""
        self.auth_values_to_try = list(range(0, 65534))
        self.sequence_values_to_try = list(range(0, 65534))
        self.status_values_to_try = list(range(0, 65534))
        self.initiate_fuzzing_logical_mode()

    def send_packet(
        self, auth_value, sequence_value, status_value, identifier, burst_number
    ):
        """send_packet"""
        global stop_thread
        global deauth_to_send_stop
        deauth_to_send_stop = 0
        toprint = 1
        stop_thread = 0
        firs = 1
        self.total_frames_to_send = 50

        for _ in range(0, self.total_frames_to_send):
            if identifier == 1:
                if firs == 1:
                    frame = infos.generate_authbody(
                        auth_value, sequence_value, status_value
                    )
                    firs = 0
                message = " eempty body frames with values : "

                infos.send_frame(frame, burst_number)
            elif identifier == 2:
                if firs == 1:
                    self.total_frames_to_send = 25
                    frame = infos.generate_custom_commit(3, 1, 0)
                    frame2 = infos.generate_authbody(
                        auth_value, sequence_value, status_value
                    )
                    firs = 0
                message = " valid commits folowed by empty body frames with values: "
                infos.send_frame(frame, burst_number)
                time.sleep(0.05)
                infos.send_frame(frame2, burst_number)
            elif identifier == 3:
                if firs == 1:
                    self.total_frames_to_send = 25
                    frame = infos.generate_custom_commit(3, 1, 0)
                    frame2 = infos.generate_custom_confirm(
                        auth_value, sequence_value, status_value, 0
                    )
                    firs = 0
                message = " valid commits folowed by confirm with send-confirm value = 0 ,, with body values : "
                infos.send_frame(frame, burst_number)
                time.sleep(0.05)
                infos.send_frame(frame2, burst_number)
            elif identifier == 4:
                if firs == 1:
                    self.total_frames_to_send = 25
                    frame = infos.generate_custom_commit(3, 1, 0)
                    frame2 = infos.generate_custom_confirm(
                        auth_value, sequence_value, status_value, 1
                    )
                    firs = 0
                message = " valid commits folowed by confirm with send-confirm value = 2 ,, with body values : "
                infos.send_frame(frame, burst_number)
                time.sleep(0.05)
                infos.send_frame(frame2, burst_number)

            elif identifier == 5:
                if firs == 1:
                    frame = infos.generate_custom_commit(
                        auth_value, sequence_value, status_value
                    )
                    firs = 0
                message = " commits with body values : "
                infos.send_frame(frame, burst_number)

            elif identifier == 6:
                if firs == 1:
                    firs = 0
                    frame = infos.generate_custom_confirm(
                        auth_value, sequence_value, status_value, 0
                    )
                message = " confirms with send-confirm value = 0 ,, with body values : "
                infos.send_frame(frame, burst_number)

            elif identifier == 7:
                if firs == 1:
                    firs = 0
                    frame = infos.generate_custom_confirm(
                        auth_value, sequence_value, status_value, 1
                    )
                message = " confirms with send-confirm value = 2 ,, with body values : "
                infos.send_frame(frame, burst_number)

            if toprint == 1:
                self.logging(
                    auth_value, sequence_value, status_value, message, burst_number
                )
                toprint = 0
                print("\n")

        time.sleep(4)
        stop_thread = 1
        if MONITORING_INTERFACE == "00":
            if deauth_to_send_stop == 1:
                print(
                    "\nFound deauthentication frames during the specific attack. "
                    "Pausing 60 sec before continuing to the next case."
                )
                time.sleep(60)
                deauth_to_send_stop = 0
        time.sleep(4)

    def logging(self, auth, seq, stat, message, burst_number):
        """logging"""
        string = f"Sending {self.total_frames_to_send}{message}{auth} {seq} {stat}"

        if int(infos.AP_CHANNEL) > 15:
            string = string + " ...  5G"
        if burst_number > 1:
            string = string + "... BURSTY"

        print(f"\n{string}")
        state.message = string


class NonResponsivenessMonitor(threading.Thread):
    """NonResponsivenessMonitor"""

    def run(self):
        global stop_all_threads
        ip_prefix = self.find_my_ip_address()
        sta_ip_address = self.find_sta_ip_address(ip_prefix)
        global start
        global toStop
        global stop_thread
        stop_thread = 1
        toStop = 0
        first = 0
        while True:
            if stop_all_threads == 1:
                break
            if stop_thread == 0:
                ping_response = self.ping_target(sta_ip_address)

                if ping_response == "notfound":
                    if first == 0:
                        first = 1
                        start_time = time.time()

                        new_list = list()
                        new_list.append(state.auth_values_to_try)
                        new_list.append(state.sequence_values_to_try)
                        new_list.append(state.status_values_to_try)

                        state.append_order(new_list)

                    print("Pinging STOPED responding")

                else:
                    if first == 1:
                        first = 0
                        end_time = time.time()
                        time_unresponsive = end_time - start_time
                        time_found = datetime.now().strftime("%H:%M:%S")
                        subprocess.call(
                            [
                                "echo ",
                                f"{time_found}. Came back online after  {time_unresponsive} of "
                                f"unresponsivness. During: {state.message} >> {nonresponsive_path}",
                            ],
                            shell=True,
                        )
                    start = 1
                    print("Pinging is responding")

                time.sleep(0.5)
            else:
                toStop = 1

                print("Stoping execution until checks")
                os.kill(os.getpid(), signal.SIGUSR2)

                if first == 1:
                    ping_response = self.ping_target(sta_ip_address)

                    fir = 1
                    while ping_response == "notfound" or ping_response == "1":
                        print("Pinging STOPED responding")
                        if fir == 1:
                            star = time.time()
                            fir = 0
                        en = time.time()
                        if en - star > 20:
                            print("calling MTI")
                            sta_ip_address = self.find_sta_ip_address(ip_prefix)

                        ping_response = self.ping_target(sta_ip_address)

                    first = 0
                    end_time = time.time()
                    time_unresponsive = end_time - start_time
                    time_found = datetime.now().strftime("%H:%M:%S")
                    subprocess.call(
                        [
                            "echo ",
                            f"{time_found}. Came back online after  {time_unresponsive}"
                            f" of unresponsivness   During: {state.message} >> {nonresponsive_path}",
                        ],
                        shell=True,
                    )
                time.sleep(1)
                toStop = 0
                start = 1
                stop_thread = 0

    def ping_target(self, sta_ip_address):
        """ping_target"""
        try:
            sa = subprocess.check_output(
                [
                    f"ping -f -c 1 -W 1 {sta_ip_address} -I {MONITORING_INTERFACE}"
                    " > /dev/null && echo found || echo notfound"
                ],
                shell=True,
            )
            sa = sa[:-1]
            return sa
        except Exception as e:
            print(f"An exception has occured: {e}")
            return "1"

    def find_my_ip_address(self):
        """Find my IP"""
        while True:
            print(
                f"\n\n{bcolors.OKGREEN}----Retrieving your ip address----{bcolors.ENDC}"
            )
            ip_prefix = subprocess.check_output(
                ['hostname -I | cut -d "." -f 1,2,3 '], shell=True
            )
            ip_prefix = ip_prefix[:-1].decode()

            if len(ip_prefix) > len("x.x.x"):
                print(f"Found ip prefix: {ip_prefix}")

                return ip_prefix

            print("Could not retrieve your ip address! Retrying in 3 seconds.")
            time.sleep(3)

    def find_sta_ip_address(self, ip_prefix):
        """Find STA IP"""
        temp = ip_prefix
        print(
            f"\n\n{bcolors.OKGREEN}----Pinging all hosts with an ip prefix of: "
            f"{ip_prefix}.xx ----{bcolors.ENDC}"
        )
        found = 0
        fe = 1
        while found == 0:
            time.sleep(0.5)
            for i in range(1, 254):
                ip_prefix += "." + str(i)
                try:
                    subprocess.call(
                        [
                            f"ping -f -c 1 -W 0.01 {ip_prefix} -I {MONITORING_INTERFACE}"
                            " > /dev/null "
                        ],
                        shell=True,
                    )
                except:
                    print("Catched. Most likely your NIC stoped working!")

                ip_prefix = temp

            try:
                sta_ip_address = subprocess.check_output(
                    [
                        f"arp -a | grep {infos.STA_MAC.lower()}"
                        ' | tr -d "()" | cut -d " " -f2'
                    ],
                    shell=True,
                )
                sta_ip_address = sta_ip_address[:-1]

            except Exception:
                print("arp -a exception.")
                sta_ip_address = "1"

            if len(sta_ip_address) > len("x.x.x"):
                print(
                    "Retrieved IP of MAC: "
                    + TARGETED_STA_MAC_ADDRESS
                    + "   is   "
                    + sta_ip_address
                    + "\n"
                )
                found = 1
                responsive = self.ping_target(sta_ip_address)
                while responsive == "notfound" or responsive == "1":
                    if responsive == "1":
                        print(
                            "Sleeping 10s because something went really wrong.Check your nic"
                        )
                        time.sleep(10)
                    else:
                        print("Pinging STOPED responding")
                    responsive = self.ping_target(sta_ip_address)

                print("is responsive")
                return sta_ip_address

            print(
                "COULD NOT FIND IP OF MAC: "
                + TARGETED_STA_MAC_ADDRESS
                + "... Retrying in 1 second!!"
            )

            if state.message != "sth":
                if fe == 1:
                    fe = 0
                    print("Disconnected")

                    new_list = list()
                    new_list.append(state.auth_values_to_try)
                    new_list.append(state.sequence_values_to_try)
                    new_list.append(state.status_values_to_try)

                    state.append_cc(new_list)

                    subprocess.call(
                        [f"echo DISCONNECTED >> {nonresponsive_path}"], shell=True
                    )

            time.sleep(0.5)


class NecessaryTests:
    """NecessaryTests"""

    def __init__(self):
        self.check_monitor_mode()
        self.check_channel()
        self.search_ap()
        self.check_sae_exchange()
        time.sleep(3)

    def thread_function(self):
        """thread_function"""
        time.sleep(0.1)

        frame = infos.generate_custom_confirm(3, 2, 0, 0)
        print("Sending CONFIRM")
        scapy.all.sendp(frame, iface=infos.ATTACKING_INTERFACE, verbose=0)

    def check_sae_exchange(self):
        """check_sae_exchange"""
        print(f"{bcolors.OKGREEN}\n\nPerforming a SAE exchange: {bcolors.ENDC}")
        frame = infos.generate_custom_commit(3, 1, 0)
        for i in range(1, 6):
            x = threading.Thread(target=self.thread_function)
            x.start()

            print("Sending COMMIT")
            answer = scapy.all.srp1(
                frame, timeout=3, iface=infos.ATTACKING_INTERFACE, inter=0.1, verbose=0
            )
            if answer:
                print(f"Exchange performed successfully on {i} try\n")
                break

            print(
                f"{bcolors.FAIL}Didnt get answer. {bcolors.ENDC} "
                f"Retrying for {i} time. Max tries: 5\n"
            )

    def check_monitor_mode(self):
        """Check Monitor Mode"""
        mode = "s"

        print(
            f"{bcolors.OKGREEN}Validating if mode of attacking interface: "
            f"{bcolors.ENDC}{bcolors.OKBLUE}{infos.ATTACKING_INTERFACE}{bcolors.ENDC}{bcolors.OKGREEN}"
            f" is set to: {bcolors.ENDC}{bcolors.OKBLUE}-- MONITOR MODE --{bcolors.ENDC}"
        )
        try:
            mode = subprocess.check_output(
                [f"iwconfig {infos.ATTACKING_INTERFACE} | grep Monitor "],
                shell=True,
            )
        except subprocess.CalledProcessError:
            mode = "1"

        if b"Monitor" not in mode:
            print(f"{infos.ATTACKING_INTERFACE} IS NOT set to monitor mode.")
            print("TERMINATING...")
            sys.exit(0)

        print(f"{infos.ATTACKING_INTERFACE} IS set to monitor mode. \n\n")

    def check_channel(self):
        """Check Channel"""
        print(
            f"{bcolors.OKGREEN}Validating if channel of: {bcolors.ENDC}"
            f"{bcolors.OKBLUE}{infos.ATTACKING_INTERFACE}{bcolors.ENDC}"
            f"{bcolors.OKGREEN} is set to: {bcolors.ENDC}"
            f"{bcolors.OKBLUE}-- {infos.AP_CHANNEL} --{bcolors.ENDC}"
        )

        try:
            channel = subprocess.check_output(
                [
                    "iw "
                    + infos.ATTACKING_INTERFACE
                    + ' info | grep channel | cut -d " " -f2'
                ],
                shell=True,
            )
        except subprocess.CalledProcessError:
            print("iw interface info | grep channel | cut -d " " -f2 returned error")
            channel = "0"

        channel = channel[:-1]
        while True:
            if channel == infos.AP_CHANNEL:
                print(
                    "Channel of "
                    + infos.ATTACKING_INTERFACE
                    + " IS set to: "
                    + infos.AP_CHANNEL
                    + "\n\n"
                )
                break

            print(
                f"Channel of {infos.ATTACKING_INTERFACE} IS NOT set to: {infos.AP_CHANNEL}"
                " OR  i cannot correctly retrieve the channel information\n"
                "You are suggested to manually check and set the interface to the correct channel (if needed)\n"
                "If you are sure that the channel is set correctly, INGORE this message.\n\n"
            )
            break

    def search_ap(self):
        """Search AP"""
        print(
            bcolors.OKGREEN
            + "Searching for AP in range, with mac address: "
            + bcolors.ENDC
            + bcolors.OKBLUE
            + "--- "
            + infos.AP_MAC
            + " ---"
            + bcolors.ENDC
        )
        print("Searching...")
        scapy.all.sniff(
            iface=infos.ATTACKING_INTERFACE, stop_filter=self.stop_filter, store=0
        )

    def stop_filter(self, pkt):
        """Stop Filter"""
        if pkt.haslayer(scapy.layers.dot11.Dot11):
            scapy.layers.dot11.Dot11_layer = pkt.getlayer(scapy.layers.dot11.Dot11)

            if isinstance(scapy.layers.dot11.Dot11_layer.addr2, str):
                if scapy.layers.dot11.Dot11_layer.addr2.lower() == infos.AP_MAC.lower():
                    print("\nAP found")
                    return True


# ----------------------#

os.system("cat src/logo.txt")

config = json.load(open("src/config.json", "r", encoding="latin1"))

AP_MAC_ADDRESS = config["AP_info"]["AP_MAC_ADDRESS"]
AP_CHANNEL = config["AP_info"]["AP_CHANNEL"]
AP_MAC_DIFFERENT_FREQUENCY = config["AP_info"]["AP_MAC_DIFFERENT_FREQUENCY"]
CHANNEL_DIFFERENT_FREQUENCY = config["AP_info"]["CHANNEL_DIFFERENT_FREQUENCY"]
TARGETED_STA_MAC_ADDRESS = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
ATTACKING_INTERFACE = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
MONITORING_INTERFACE = config["ATT_interface_info"]["MONITORING_INTERFACE"]
PASSWORD = config["AP_info"]["PASSWORD"]


terminal_width = int(subprocess.check_output(["stty", "size"]).split()[1])
print("\n")
print("-" * terminal_width)
print(
    f"{bcolors.OKGREEN}INFORMATION RETRIEVED FROM CONFIG FILE{bcolors.ENDC}".center(
        terminal_width
    )
)
print(f"  {bcolors.STH}AP_MAC:   {AP_MAC_ADDRESS}{bcolors.ENDC}".center(terminal_width))
print(f"  {bcolors.STH}AP_CHANNEL:   {AP_CHANNEL}{bcolors.ENDC}".center(terminal_width))
print("\n")
print(
    (
        f"{bcolors.STH}AP_MAC_DIFFERENT_FREQUENCY:   "
        f"{AP_MAC_DIFFERENT_FREQUENCY}{bcolors.ENDC}"
    ).center(terminal_width)
)
print(
    (
        f"  {bcolors.STH}CHANNEL_DIFFERENT_FREQUENCY:   "
        f"{CHANNEL_DIFFERENT_FREQUENCY}{bcolors.ENDC}"
    ).center(terminal_width)
)
print("\n")
print(
    (
        f"  {bcolors.STH}TARGETED_STA_MAC_ADDRESS:   "
        f"{TARGETED_STA_MAC_ADDRESS}{bcolors.ENDC}"
    ).center(terminal_width)
)
print("\n")
print(
    (
        f"  {bcolors.STH}ATTACKING INTERFACE:   " f"{ATTACKING_INTERFACE}{bcolors.ENDC}"
    ).center(terminal_width)
)
print(
    (
        f"  {bcolors.STH}MONITORING INTERFACE:   "
        f"{MONITORING_INTERFACE}{bcolors.ENDC}"
    ).center(terminal_width)
)
print("\n")
print(
    ("  " + bcolors.STH + "PASSWORD:   " + PASSWORD + bcolors.ENDC).center(
        terminal_width
    )
)
print("-" * terminal_width)

infos = Generate_Frames(
    AP_MAC_ADDRESS,
    AP_CHANNEL,
    AP_MAC_DIFFERENT_FREQUENCY,
    CHANNEL_DIFFERENT_FREQUENCY,
    TARGETED_STA_MAC_ADDRESS,
    ATTACKING_INTERFACE,
    MONITORING_INTERFACE,
    PASSWORD,
)

print(f"Checking for '{ATTACKING_INTERFACE}'")
try:
    check_interface = subprocess.check_output(
        [f"iw dev {ATTACKING_INTERFACE} info"], shell=True, stderr=subprocess.STDOUT
    )
except Exception as exception:
    print(
        f"Unable to find: '{ATTACKING_INTERFACE}', due to: {exception.stdout.decode()}"
    )
    sys.exit(0)

print(f"Interface '{MONITORING_INTERFACE}' found\n")

print(f"Checking for '{MONITORING_INTERFACE}'")
try:
    check_interface = subprocess.check_output(
        [f"iw dev {MONITORING_INTERFACE} info"], shell=True, stderr=subprocess.STDOUT
    )
except Exception as exception:
    print(
        f"Unable to find: '{MONITORING_INTERFACE}', due to: {exception.stdout.decode()}"
    )
    sys.exit(0)

print(f"Interface '{MONITORING_INTERFACE}' found\n")


folder_name = datetime.now().strftime("fuzz%d-%m-%y__%H:%M:%S")
folder_path = f"logs/{folder_name}"
deauth_path = f"{folder_path}/deauth.txt"
nonresponsive_path = f"{folder_path}/nonresponsive.txt"

subprocess.call(["mkdir -p logs"], shell=True)
subprocess.call([f"mkdir {folder_path}"], shell=True)
subprocess.call([f"touch {deauth_path}"], shell=True)
subprocess.call([f"touch {nonresponsive_path}"], shell=True)


state = SaveState()

fuzz = Fuzz()

NecessaryTests = NecessaryTests()

global start
start = 0

if CHANNEL_DIFFERENT_FREQUENCY == "00":
    print("Skipping attack on the other frequency\n")


thread2 = deauth_Monitor()
thread2.start()
time.sleep(1)

if MONITORING_INTERFACE == "00":
    print("\nProcceding without NON-RESPONSIVNESS MONITORING!")
    start = 1
else:
    thread1 = NonResponsivenessMonitor()
    thread1.start()


global stop_all_threads
stop_all_threads = 0

while True:
    if start == 1:
        fuzz.initiate_fuzzing_logical_mode()
        graphs.statisticss(nonresponsive_path, state.order_values)
        stop_all_threads = 1

        # fuzz.initiate_Fuzzing_EXTENDED_MODE()
        print("\n\nFUZZING FINISHED!")

        sys.exit(0)
