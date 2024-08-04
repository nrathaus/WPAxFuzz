"""Fuzzer Init"""
import json

with open("src/config.json", "r", encoding="latin1") as file_handle:
    config = json.load(file_handle)

targeted_access_point = config["AP_info"]["AP_MAC_ADDRESS"]
att_interface = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
targeted_sta = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
real_ap_ssid = config["AP_info"]["AP_SSID"]
