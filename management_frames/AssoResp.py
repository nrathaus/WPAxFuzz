"""Association Response"""
from random import randint

import scapy.all
import scapy.layers.dot11

from management_frames.Construct_frame_fields import (
    STANDARD_EXT_HT_CAPABILITIES,
    STANDARD_HT_CAPABILITIES,
    STANDARD_HT_INFORMATION,
    STANDARD_OVERLAPPING_BSS,
    SUPPL_RATES,
    SUPPORTED_RATES,
    Frame,
)


class AssoResp(Frame):
    """Association Response"""

    def __init__(self, mode, frame_name, dest_addr, source_addr, interface, direction):
        super(AssoResp, self).__init__()
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.direction = direction
        self.fuzzer_state = {
            "empty": {"send_function": self.MAC_header, "conn_loss": False},
            "capabilities": {
                "send_function": self.send_asso_resp_with_rand_capabilities,
                "conn_loss": False,
            },
            "supported rates": {
                "send_function": self.send_asso_resp_with_rand_supp_speed,
                "conn_loss": False,
            },
            "HT capabilities": {
                "send_function": self.send_asso_resp_with_rand_ht_capabilities,
                "conn_loss": False,
            },
            "HT information": {
                "send_function": self.send_asso_resp_with_rand_ht_information,
                "conn_loss": False,
            },
            "overlapping BSS scan parameters": {
                "send_function": self.send_asso_resp_with_rand_overlapping_bss,
                "conn_loss": False,
            },
            "extended capabilities": {
                "send_function": self.send_asso_resp_with_rand_extended_ht_caps,
                "conn_loss": False,
            },
            "source MACs": {
                "send_function": self.send_asso_resp_with_rand_source_mac,
                "conn_loss": False,
            },
            "all fields": {
                "send_function": self.send_asso_resp_with_all_fields_rand,
                "conn_loss": False,
            },
        }

    def mac_header(self, mode):
        """MAC_header"""
        if mode == "standard":
            MAC_header = self.construct_mac_header(
                1, self.dest_addr, self.source_addr, self.source_addr
            )
        elif mode == "random":
            if self.direction == 1:
                MAC_header = self.construct_mac_header(
                    1, self.dest_addr, self.source_addr, self.source_addr
                )
            elif self.direction == 2:
                MAC_header = self.construct_mac_header(
                    1, self.source_addr, self.dest_addr, self.source_addr
                )
        return MAC_header

    def send_asso_resp_with_rand_source_mac(self, mode):
        """send_asso_resp_with_rand_source_mac"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_HT_CAPABILITIES
            / STANDARD_HT_INFORMATION
            / STANDARD_OVERLAPPING_BSS
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_capabilities(self, mode):
        """send_asso_resp_with_rand_capabilities"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=randint(1, 9999))
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_HT_CAPABILITIES
            / STANDARD_HT_INFORMATION
            / STANDARD_OVERLAPPING_BSS
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_supp_speed(self, mode):
        """send_asso_resp_with_rand_supp_speed"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / self.generate_supp_speed(mode)
            / STANDARD_HT_CAPABILITIES
            / STANDARD_HT_INFORMATION
            / STANDARD_OVERLAPPING_BSS
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_ht_capabilities(self, mode):
        """send_asso_resp_with_rand_ht_capabilities"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / self.generate_ht_capabilities(mode)
            / STANDARD_HT_INFORMATION
            / STANDARD_OVERLAPPING_BSS
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_ht_information(self, mode):
        """send_asso_resp_with_rand_ht_information"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_HT_CAPABILITIES
            / self.generate_ht_information(mode)
            / STANDARD_OVERLAPPING_BSS
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_overlapping_bss(self, mode):
        """send_asso_resp_with_rand_overlapping_bss"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_HT_CAPABILITIES
            / STANDARD_HT_INFORMATION
            / self.generate_overlapping_bss(mode)
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_asso_resp_with_rand_extended_ht_caps(self, mode):
        """send_asso_resp_with_rand_extended_ht_caps"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=4920)
        frame = (
            self.mac_header(mode)
            / asso_resp
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_HT_CAPABILITIES
            / STANDARD_HT_INFORMATION
            / STANDARD_OVERLAPPING_BSS
            / self.generate_extended_ht_capabilities(mode)
        )
        return frame

    def send_asso_resp_with_all_fields_rand(self, mode):
        """send_asso_resp_with_all_fields_rand"""
        asso_resp = scapy.layers.dot11.Dot11AssoResp(cap=randint(1, 9999))
        frame = (
            self.mac_header(mode)
            / asso_resp
            / self.generate_supp_speed(mode)
            / self.generate_ht_capabilities(mode)
            / self.generate_ht_information(mode)
            / self.generate_overlapping_bss(mode)
            / self.generate_extended_ht_capabilities(mode)
        )
        return frame

    def fuzz_asso_resp(self):
        """fuzz_asso_resp"""
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
