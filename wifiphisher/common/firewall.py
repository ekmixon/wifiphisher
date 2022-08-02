"""Serves as an abstraction layer in front of iptables."""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from wifiphisher.common.constants import NETWORK_GW_IP, PORT, SSL_PORT
from wifiphisher.common.utilities import execute_commands


class Fw():
    """Handles all iptables operations."""

    @staticmethod
    def nat(internal_interface, external_interface):
        # type: (str, str) -> None
        """Do NAT."""
        execute_commands(
            [
                f"iptables -t nat -A POSTROUTING -o {external_interface} -j MASQUERADE",
                f"iptables -A FORWARD -i {internal_interface} -o {external_interface} -j ACCEPT",
            ]
        )

    @staticmethod
    def clear_rules():
        # type: () -> None
        """Clear all rules."""
        execute_commands([
            "iptables -F", "iptables -X", "iptables -t nat -F",
            "iptables -t nat -X"
        ])

    @staticmethod
    def redirect_requests_localhost():
        # type: () -> None
        """Redirect HTTP, HTTPS & DNS requests to localhost.

        Redirect the following requests to localhost:
            * HTTP (Port 80)
            * HTTPS (Port 443)
            * DNS (Port 53)
        """
        execute_commands(
            [
                f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination {NETWORK_GW_IP}:{PORT}",
                f"iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination {NETWORK_GW_IP}:53",
                f"iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination {NETWORK_GW_IP}:53",
                f"iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination {NETWORK_GW_IP}:{SSL_PORT}",
            ]
        )

    def on_exit(self):
        # type: () -> None
        """Start the clean up."""
        self.clear_rules()
