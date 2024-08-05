"""aliveness_check Check"""
import subprocess
import sys
import threading
import time

import settings
from message_colors import bcolors


class AllvCheck(threading.Thread):
    def __init__(self, targeted_sta, mode):
        super(AllvCheck, self).__init__()
        self.targeted_sta = targeted_sta
        self.mode = mode

    def run(self):
        """Run"""
        ip_prefix = self.find_lan_prefix()
        targeted_sta_IP = self.find_ip_address_of_sta(ip_prefix)
        if self.mode == "fuzzing":
            while True:
                time.sleep(1)
                ping_response = self.ping_target(targeted_sta_IP)
                if ping_response == "found":
                    pass
                elif ping_response == "notfound":
                    settings.is_alive = False
                    print(f"\n{bcolors.FAIL}STA is unresponsive{bcolors.ENDC}\n")
                    while True:
                        input(
                            f"{bcolors.WARNING}Reconnect the STA and press Enter to resume:\n"
                            f"{bcolors.ENDC}"
                        )
                        if self.ping_target(targeted_sta_IP) == "found":
                            print(
                                f"{bcolors.OKCYAN}Pausing for 20s and proceeding to the "
                                f"next subtype of frames{bcolors.ENDC}\n"
                            )
                            time.sleep(20)
                            settings.is_alive = True
                            settings.conn_loss = False
                            break
        elif self.mode == "attacking":
            while True:
                time.sleep(1)
                ping_response = self.ping_target(targeted_sta_IP)
                if ping_response == "found":
                    pass
                elif ping_response == "notfound":
                    settings.is_alive = False

    def ping_target(self, sta_ip_address):
        """ping_target"""
        try:
            sa = subprocess.check_output(
                [
                    "ping -f -c 1 -W 1 "
                    + sta_ip_address
                    + " > /dev/null && echo found || echo notfound"
                ],
                shell=True,
            )
            sa = sa[:-1]
            return sa.decode("utf-8")
        except Exception as e:
            print(f"An exception has occured: {e}")
            return "1"

    def find_lan_prefix(self):
        """find LAN prefix"""
        while True:
            print(
                f"\n\n{bcolors.OKGREEN}----Retrieving your IP address----{bcolors.ENDC}"
            )
            ip_prefix = subprocess.check_output(
                ['hostname -I | cut -d "." -f 1,2,3'], shell=True
            )
            ip_prefix = ip_prefix[:-1].decode("utf-8")

            if len(ip_prefix) > len("x.x.x"):
                print(f"\nFound IP prefix: '{ip_prefix}' ")
                return ip_prefix

            print("Could not retrieve your IP address! Retrying in 3s.")
            time.sleep(3)

    def find_ip_address_of_sta(self, ip_prefix):
        """find_ip_address_of_sta"""
        temp = ip_prefix
        print(
            f"\n\n{bcolors.OKGREEN}----Pinging all hosts with an IP prefix of: "
            f"{ip_prefix}.xx----{bcolors.ENDC}\n"
            f"Trying to locate Targeted STA MAC address: '{self.targeted_sta}'"
        )

        found = False
        while not found:
            time.sleep(0.5)
            for i in range(1, 254):
                ip_prefix += "." + str(i)
                try:
                    subprocess.call(
                        [f"ping -f -c 1 -W 0.01 {ip_prefix} > /dev/null"],
                        shell=True,
                    )
                except:
                    print("Catched. Most likely your WNIC has stopped working!")

                ip_prefix = temp
                try:
                    sta_ip_address = subprocess.check_output(
                        [
                            f'arp -a | grep {self.targeted_sta} | tr -d "()" | cut -d " " -f2'
                        ],
                        shell=True,
                    )
                    sta_ip_address = sta_ip_address[:-1].decode("utf-8")
                except Exception as e:
                    print(f"arp -a exception. Exception: {e}")
                    sta_ip_address = "1"

                if len(sta_ip_address) > len("x.x.x"):
                    print(
                        f"\nRetrieved IP of MAC: '{self.targeted_sta}' is '{sta_ip_address}'\n"
                    )
                    found = 1
                    responsive = self.ping_target(sta_ip_address)

                    while responsive == "notfound" or responsive == "1":
                        if (
                            responsive == "1"
                        ):  # look at ping_target function, exception has been triggered
                            print(
                                "Sleeping 10s because something went really wrong. Check your WNIC"
                            )
                            time.sleep(10)
                        else:
                            print(
                                "\n"
                                + bcolors.WARNING
                                + "Pinging stopped responding"
                                + bcolors.ENDC
                            )
                            input(
                                bcolors.WARNING
                                + "Get the STA back online and press enter: "
                                + bcolors.ENDC
                            )
                        responsive = self.ping_target(sta_ip_address)

                    print("\nSTA is responsive")
                    settings.retrieving_ip_address = True
                    return sta_ip_address

                print(
                    "\n"
                    + bcolors.FAIL
                    + "Could not find the IP of MAC: "
                    + bcolors.ENDC
                    + self.targeted_sta
                )
                settings.ip_address_not_alive = True
                settings.retrieving_ip_address = True
                sys.exit(0)
