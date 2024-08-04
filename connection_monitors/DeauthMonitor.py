"""Deauth Monitor"""
import threading

import scapy.all
import scapy.layers.dot11

import settings


class DeauthMon(threading.Thread):
    def __init__(self, targeted_access_point, targeted_sta, att_interface):
        super(DeauthMon, self).__init__()
        self.targeted_access_point = targeted_access_point
        self.targeted_sta = targeted_sta
        self.att_interface = att_interface

    def run(self):
        """Run"""
        while settings.conn_loss or not settings.is_alive:
            pass
        scapy.all.sniff(
            iface=self.att_interface,
            store=0,
            stop_filter=self.stop_filter,
            filter=(
                "(ether dst "
                + self.targeted_sta
                + " and ether src "
                + self.targeted_access_point
                + ") or (ether dst "
                + self.targeted_access_point
                + " and ether src "
                + self.targeted_sta
                + ")"
            ),
        )

    def stop_filter(self, packet):
        """Stop Filter"""
        keyword1 = "Deauthentification"
        keyword2 = "Disassociate"
        if (
            packet.haslayer(scapy.layers.dot11.Dot11Deauth)
            or keyword1 in packet.summary()
        ):
            settings.conn_loss = True
        elif (
            packet.haslayer(scapy.layers.dot11.Dot11Disas)
            or keyword2 in packet.summary()
        ):
            settings.conn_loss = True
        else:
            pass
