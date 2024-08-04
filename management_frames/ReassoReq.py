"""Reasso Req"""
from random import randint

import scapy.layers.dot11

from management_frames.Construct_frame_fields import (
    STANDARD_EXT_HT_CAPABILITIES,
    STANDARD_HT_CAPABILITIES,
    STANDARD_MAC_ADDRESS,
    STANDARD_POWER_CAPS,
    STANDARD_RM_CAPS,
    STANDARD_RSN,
    STANDARD_SUPP_CHANNELS,
    SUPPL_RATES,
    SUPPORTED_RATES,
    Frame,
)


class ReassoReq(Frame):
    def __init__(self, mode, frame_name, dest_addr, source_addr, interface, ssid):
        super(ReassoReq, self).__init__()
        self.mode = mode
        self.frame_name = frame_name
        self.dest_addr = dest_addr
        self.source_addr = source_addr
        self.interface = interface
        self.ssid = scapy.layers.dot11.Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        self.fuzzer_state = {
            "empty": {"send_function": self.send_empty_reasso_req, "conn_loss": False},
            "capabilities": {
                "send_function": self.send_reasso_req_with_rand_capabilities,
                "conn_loss": False,
            },
            "current AP": {
                "send_function": self.send_reasso_req_with_rand_current_ap,
                "conn_loss": False,
            },
            "supported rates": {
                "send_function": self.send_reasso_req_with_rand_supp_speed,
                "conn_loss": False,
            },
            "power capabilities": {
                "send_function": self.send_reasso_req_with_rand_power_caps,
                "conn_loss": False,
            },
            "supported channels": {
                "send_function": self.send_reasso_req_with_rand_supp_channels,
                "conn_loss": False,
            },
            "RSNs": {
                "send_function": self.send_reasso_req_with_rand_rsn,
                "conn_loss": False,
            },
            "RM enabled capabilities": {
                "send_function": self.send_reasso_req_with_rand_rm_caps,
                "conn_loss": False,
            },
            "HT capabilities": {
                "send_function": self.send_reasso_req_with_rand_ht_capabilities,
                "conn_loss": False,
            },
            "extended HT capabilities": {
                "send_function": self.send_reasso_req_with_rand_ext_ht_capabilities,
                "conn_loss": False,
            },
            "source MACs": {
                "send_function": self.send_reasso_req_with_rand_source_mac,
                "conn_loss": False,
            },
            "all fields": {
                "send_function": self.send_reasso_req_with_all_fields_rand,
                "conn_loss": False,
            },
        }

    def send_empty_reasso_req(self, mode):
        """send_empty_reasso_req"""
        return self.construct_mac_header(
            2, self.dest_addr, self.source_addr, self.dest_addr
        )

    def send_reasso_req_with_rand_rsn(self, mode):
        """send_reasso_req_with_rand_rsn"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / self.construct_rsn(mode)
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_source_mac(self, mode):
        """send_reasso_req_with_rand_source_mac"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.generate_mac(), self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_current_ap(self, mode):
        """send_reasso_req_with_rand_current_ap"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=self.generate_mac()
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_capabilities(self, mode):
        """send_reasso_req_with_rand_capabilities"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=randint(1, 9999), current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_supp_speed(self, mode):
        """send_reasso_req_with_rand_supp_speed"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / self.generate_supp_speed(mode)
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_ht_capabilities(self, mode):
        """send_reasso_req_with_rand_ht_capabilities"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / self.generate_ht_capabilities(mode)
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_ext_ht_capabilities(self, mode):
        """send_reasso_req_with_rand_ext_ht_capabilities"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / self.generate_extended_ht_capabilities(mode)
        )
        return frame

    def send_reasso_req_with_rand_power_caps(self, mode):
        """send_reasso_req_with_rand_power_caps"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / self.generate_power_capability(mode)
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_supp_channels(self, mode):
        """send_reasso_req_with_rand_supp_channels"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / self.generate_supported_channels(mode)
            / STANDARD_RSN
            / STANDARD_RM_CAPS
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_rand_rm_caps(self, mode):
        """send_reasso_req_with_rand_rm_caps"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=4920, current_AP=STANDARD_MAC_ADDRESS
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / SUPPORTED_RATES
            / SUPPL_RATES
            / STANDARD_POWER_CAPS
            / STANDARD_SUPP_CHANNELS
            / STANDARD_RSN
            / self.generate_rm_enabled_capabilities(mode)
            / STANDARD_HT_CAPABILITIES
            / STANDARD_EXT_HT_CAPABILITIES
        )
        return frame

    def send_reasso_req_with_all_fields_rand(self, mode):
        """send_reasso_req_with_all_fields_rand"""
        reasso_req = scapy.layers.dot11.Dot11ReassoReq(
            cap=randint(1, 9999), current_AP=self.generate_mac()
        )
        frame = (
            self.construct_mac_header(
                2, self.dest_addr, self.source_addr, self.dest_addr
            )
            / reasso_req
            / self.ssid
            / self.generate_supp_speed(mode)
            / self.generate_power_capability(mode)
            / self.generate_supported_channels(mode)
            / self.construct_rsn(mode)
            / self.generate_rm_enabled_capabilities(mode)
            / self.generate_ht_capabilities(mode)
            / self.generate_extended_ht_capabilities(mode)
        )
        return frame

    def fuzz_reasso_req(self):
        """fuzz_reasso_req"""
        self.fuzz(self.mode, self.fuzzer_state, self.interface)
