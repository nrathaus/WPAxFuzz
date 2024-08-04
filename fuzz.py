#!/usr/bin/python3
import subprocess
import sys
import time

import ascii_art
import settings
from connection_monitors.AlivenessCheck import AllvCheck
from connection_monitors.DeauthMonitor import DeauthMon
from ctrl_frames.ControlFrames import ControlFrames
from data_frames.DataFrames import DataFrames
from fuzzer_init import att_interface, real_ap_ssid, targeted_access_point, targeted_sta
from management_frames.AssoReq import AssoReq
from management_frames.AssoResp import AssoResp
from management_frames.Authentication import Authentication
from management_frames.Beacon import Beacon
from management_frames.Probe_request import ProbeReq
from management_frames.Probe_response import Proberesp
from management_frames.ReassoReq import ReassoReq
from management_frames.ReassoResp import ReassoResp
from message_colors import bcolors

issue_clears = False

print(ascii_art.logo)
print(("- " * 62) + "\n\n")
print(
    "\t\tThis tool is capable of fuzzing either any management, control or data frame of the 802.11\n"
    "\t\tprotocol or the SAE exchange. For the management, control or data frames, you can choose\n"
    '\t\teither the "standard" mode where all of the frames transmitted have valid size values or\n'
    '\t\tthe "random" mode where the size value is random. The SAE fuzzing operation requires an AP\n'
    "\t\tthat supports WPA3. Management, control or data frame fuzzing can be executed against any AP\n"
    "\t\t(WPA2 or WPA3). Finally, a DoS attack vector is implemented, which exploits the findings of\n"
    "\t\tthe management, control or data frames fuzzing.\n"
)
print(("- " * 62) + "\n\n")

print("1) Fuzz Management Frames")
print("2) Fuzz SAE exchange")
print("3) Fuzz Control Frames")
print(f"4) Fuzz Data Frames {bcolors.WARNING}(BETA){bcolors.ENDC}")
print("5) DoS attack module\n\n")
try:
    choice = int(input("Enter a choice: "))
except:
    print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
    sys.exit(0)


def dos_attack_module():
    """dos_attack_module"""
    if issue_clears:
        subprocess.call(["clear"], shell=True)
    subprocess.call(["sudo python3 mage.py"], shell=True)


def fuzz_data_frames():
    """fuzz_data_frames"""
    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.data_frames)
    print('Type "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input("Enter a choice: ").lower()
    if mode == "standard" or mode == "random":
        aliveness_check = AllvCheck(targeted_sta, "fuzzing")
        aliveness_check.start()
        while not settings.retrieving_ip_address:
            if settings.ip_address_not_alive:
                sys.exit(0)
        time.sleep(10)
        if issue_clears:
            subprocess.call(["clear"], shell=True)
    else:
        print(bcolors.FAIL + "\nNo such mode :(" + bcolors.ENDC)
        sys.exit(0)

    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.data_frames)
    print("1) Target the STA and impersonate the AP")
    print("2) Target the AP and impersonate the STA\n\n")
    try:
        direction = int(input("Select a frame to fuzz: "))
    except:
        print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
        sys.exit(0)

    if direction in {1, 2}:
        pass
    else:
        print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
        sys.exit(0)

    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.data_frames)
    print("Which frames would you like to fuzz?")
    print("1) Data")
    print("2) Data + CF-ACK")
    print("3) Data + CF-Poll")
    print("4) Data + CF-Ack + CF-Poll")
    print("5) Null Data")
    print("6) CF-ACK (no data)")
    print("7) CF-Poll (no data)")
    print("8) CF-ACK + CF-Poll (no data)")
    print("9) QoS Data")
    print("10) QoS Data + CF-ACK")
    print("11) QoS Data + CF-Poll")
    print("12) QoS Data + CF-ACK + CF-Poll")
    print("13) QoS Null Data")
    print("14) Reserved Data Frame")
    print("15) QoS Data + CF-Poll (no data)")
    print("16) QoS CF-ACK + CF-Poll (no data)\n\n")
    try:
        choice2 = int(input("Select a frame to fuzz: "))
    except:
        print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
        sys.exit(0)

    if direction == 1:
        fuzz_data = DataFrames(
            targeted_sta, targeted_access_point, att_interface, mode, choice2, True
        )
    else:
        fuzz_data = DataFrames(
            targeted_access_point, targeted_sta, att_interface, mode, choice2, False
        )

    if issue_clears:
        subprocess.call(["clear"], shell=True)

    print(ascii_art.data_frames)
    print(ascii_art.wifi)
    print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
    time.sleep(5)
    print(fuzz_data.fuzz_data_frames())


def fuzz_control_frames():
    """fuzz_control_frames"""
    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.control_frames)
    print('Type "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input("Enter a choice: ").lower()
    if mode == "standard" or mode == "random":
        aliveness_check = AllvCheck(targeted_sta, "fuzzing")
        aliveness_check.start()
        while not settings.retrieving_ip_address:
            if settings.ip_address_not_alive:
                sys.exit(0)
        time.sleep(10)
        if issue_clears:
            subprocess.call(["clear"], shell=True)
    else:
        print(bcolors.FAIL + "\nNo such mode :(" + bcolors.ENDC)
        sys.exit(0)

    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.control_frames)
    print("1) Target the STA and impersonate the AP")
    print("2) Target the AP and impersonate the STA\n\n")
    try:
        direction = int(input("Select a frame to fuzz: "))
    except:
        print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
        sys.exit(0)

    if direction in {1, 2}:
        pass
    else:
        print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
        sys.exit(0)

    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.control_frames)
    print("Which frames would you like to fuzz?")
    print("1) Beamforming Report Poll")
    print("2) VHT/HE NDP Announcement")
    print("3) Control Frame Extension")
    print("4) Control wrapper")
    print("5) Block Ack Request (BAR)")
    print("6) Block ACK")
    print("7) PS-Poll (Power Save-Poll)")
    print("8) RTS–Request to Send")
    print("9) CTS-Clear to Send")
    print("10) ACK")
    print("11) CF-End (Contention Free-End)")
    print("12) CF-End & CF-ACK\n\n")
    try:
        choice2 = int(input("Select a frame to fuzz: "))
    except:
        print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
        sys.exit(0)

    if choice2 == 3:
        if issue_clears:
            subprocess.call(["clear"], shell=True)
        print(ascii_art.control_frames)
        print("Which frames would you like to fuzz?")
        print("1) Poll")
        print("2) Service period request")
        print("3) Grant")
        print("4) DMG CTS")
        print("5) DMG DTS")
        print("6) Grant Ack")
        print("7) Sector sweep (SSW)")
        print("8) Sector sweep feedback (SSW-Feedback)")
        print("9) Sector sweep Ack (SSW-Ack)\n\n")
        try:
            choice3 = int(input("Select a frame to fuzz: "))
        except:
            print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
            sys.exit(0)

        if direction == 1:
            fuzz_ctrl = ControlFrames(
                targeted_sta,
                targeted_access_point,
                att_interface,
                mode,
                choice2,
                choice3 + 1,
            )
        else:
            fuzz_ctrl = ControlFrames(
                targeted_access_point,
                targeted_sta,
                att_interface,
                mode,
                choice2,
                choice3 + 1,
            )
    else:
        if direction == 1:
            fuzz_ctrl = ControlFrames(
                targeted_sta, targeted_access_point, att_interface, mode, choice2, 0
            )
        else:
            fuzz_ctrl = ControlFrames(
                targeted_access_point, targeted_sta, att_interface, mode, choice2, 0
            )

    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.control_frames)
    print(ascii_art.wifi)
    print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
    time.sleep(5)
    print(fuzz_ctrl.fuzz_ctrl_frames())


def fuzz_sae_exchange():
    """fuzz_sae_exchange"""
    if issue_clears:
        subprocess.call(["clear"], shell=True)
    subprocess.call(["sudo python3 dos-sae.py"], shell=True)


def fuzz_management_frames():
    """fuzz_management_frames"""
    if issue_clears:
        subprocess.call(["clear"], shell=True)
    print(ascii_art.mngmt_frames)
    print('Type "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input("Enter a choice: ").lower()
    if mode in ["standard", "random"]:
        aliveness_check = AllvCheck(targeted_sta, "fuzzing")
        aliveness_check.start()
        while not settings.retrieving_ip_address:
            if settings.ip_address_not_alive:
                sys.exit(0)

        time.sleep(10)
        if issue_clears:
            subprocess.call(["clear"], shell=True)
    else:
        print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
        sys.exit(0)

    if issue_clears:
        subprocess.call(["clear"], shell=True)

    print(ascii_art.mngmt_frames)
    print("Which frames would you like to fuzz?")
    print("1) Beacon frames")
    print("2) Probe request frames")
    print("3) Probe response frames")
    print("4) Association request frames")
    print("5) Association response frames")
    print("6) Reassociation request frames")
    print("7) Reassociation response frames")
    print("8) Authentication frames\n\n")
    try:
        choice2 = int(input("Select a frame to fuzz: "))
    except:
        print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
        sys.exit(0)

    deauth_monitor = DeauthMon(targeted_access_point, targeted_sta, att_interface)
    deauth_monitor.start()
    if choice2 == 1:
        if mode == "random":
            if issue_clears:
                subprocess.call(["clear"], shell=True)

            print(ascii_art.beacon)
            print(ascii_art.wifi)
            print("1) Target the STA and impersonate the AP")
            print("2) Target the AP and impersonate the STA\n\n")
            try:
                direction = int(input("Select a frame to fuzz: "))
            except:
                print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
                sys.exit(0)

            if direction in {1, 2}:
                pass
            else:
                print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
                sys.exit(0)
        else:
            direction = 1
        fuzz_beacons = Beacon(
            mode,
            "beacon",
            targeted_sta,
            targeted_access_point,
            att_interface,
            real_ap_ssid,
            direction,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)

        print(ascii_art.beacon)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_beacons.fuzz_beacon()
    elif choice2 == 2:
        fuzz_probe_reqs = ProbeReq(
            mode,
            "probe request",
            targeted_access_point,
            targeted_sta,
            att_interface,
            real_ap_ssid,
        )

        if issue_clears:
            subprocess.call(["clear"], shell=True)

        print(ascii_art.probe_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_probe_reqs.fuzz_probe_req()
    elif choice2 == 3:
        if mode == "random":
            if issue_clears:
                subprocess.call(["clear"], shell=True)
            print(ascii_art.probe_resp)
            print(ascii_art.wifi)
            print("1) Target the STA and impersonate the AP")
            print("2) Target the AP and impersonate the STA\n\n")
            try:
                direction = int(input("Select a frame to fuzz: "))
            except:
                print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
                sys.exit(0)

            if direction in {1, 2}:
                pass
            else:
                print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
                sys.exit(0)
        else:
            direction = 1
        fuzz_probe_resp = Proberesp(
            mode,
            "probe response",
            targeted_sta,
            targeted_access_point,
            att_interface,
            real_ap_ssid,
            direction,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)

        print(ascii_art.probe_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_probe_resp.fuzz_probe_resp()
    elif choice2 == 4:
        fuzz_asso_reqs = AssoReq(
            mode,
            "association request",
            targeted_access_point,
            targeted_sta,
            att_interface,
            real_ap_ssid,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)

        print(ascii_art.asso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_asso_reqs.fuzz_asso_req()
    elif choice2 == 5:
        if mode == "random":
            if issue_clears:
                subprocess.call(["clear"], shell=True)
            print(ascii_art.asso_resp)
            print(ascii_art.wifi)
            print("1) Target the STA and impersonate the AP")
            print("2) Target the AP and impersonate the STA\n\n")
            try:
                direction = int(input("Select a frame to fuzz: "))
            except:
                print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
                sys.exit(0)

            if direction in {1, 2}:
                pass
            else:
                print(f"{bcolors.FAIL}\nNo such mode :({bcolors.ENDC}")
                sys.exit(0)
        else:
            direction = 1
        fuzz_asso_resp = AssoResp(
            mode,
            "association response",
            targeted_sta,
            targeted_access_point,
            att_interface,
            direction,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)
        print(ascii_art.asso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_asso_resp.fuzz_asso_resp()
    elif choice2 == 6:
        fuzz_reasso_reqs = ReassoReq(
            mode,
            "reassociation request",
            targeted_access_point,
            targeted_sta,
            att_interface,
            real_ap_ssid,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)
        print(ascii_art.reasso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_reasso_reqs.fuzz_reasso_req()
    elif choice2 == 7:
        if mode == "random":
            if issue_clears:
                subprocess.call(["clear"], shell=True)
            print(ascii_art.reasso_resp)
            print(ascii_art.wifi)
            print("1) Target the STA and impersonate the AP")
            print("2) Target the AP and impersonate the STA\n\n")
            try:
                direction = int(input("Select a frame to fuzz: "))
            except:
                print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
                sys.exit(0)

            if direction in {1, 2}:
                pass
            else:
                print(bcolors.FAIL + "\nNo such mode :(" + bcolors.ENDC)
                sys.exit(0)
        else:
            direction = 1
        fuzz_asso_resp = ReassoResp(
            mode,
            "reassociation response",
            targeted_sta,
            targeted_access_point,
            att_interface,
            direction,
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)
        print(ascii_art.reasso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_asso_resp.fuzz_reasso_resp()
    elif choice2 == 8:
        fuzz_auth = Authentication(
            mode, "authentication", targeted_access_point, targeted_sta, att_interface
        )
        if issue_clears:
            subprocess.call(["clear"], shell=True)
        print(ascii_art.auth)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        time.sleep(5)
        fuzz_auth.fuzz_auth()


#
# Main choices
#
if choice == 1:
    fuzz_management_frames()
elif choice == 2:
    fuzz_sae_exchange()
elif choice == 3:
    fuzz_control_frames()
elif choice == 4:
    fuzz_data_frames()
elif choice == 5:
    dos_attack_module()
else:
    print(f"{bcolors.FAIL}\nNo such choice :({bcolors.ENDC}")
