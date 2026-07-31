import pytest
from unittest.mock import mock_open, patch
from src.mac_lookup import get_mac_for_ip

def test_get_mac_for_ip_found():
    proc_net_arp = "IP address       HW type     Flags       HW address            Mask     Device\n" \
                   "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
    
    with patch("builtins.open", mock_open(read_data=proc_net_arp)):
        mac = get_mac_for_ip("192.168.1.1")
        assert mac == "aa:bb:cc:dd:ee:ff"

def test_get_mac_for_ip_not_found():
    proc_net_arp = "IP address       HW type     Flags       HW address            Mask     Device\n" \
                   "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n"
    
    with patch("builtins.open", mock_open(read_data=proc_net_arp)):
        mac = get_mac_for_ip("10.0.0.1")
        assert mac is None

def test_get_mac_for_ip_zero_mac():
    proc_net_arp = "IP address       HW type     Flags       HW address            Mask     Device\n" \
                   "192.168.1.1      0x1         0x2         00:00:00:00:00:00     *        eth0\n"
    
    with patch("builtins.open", mock_open(read_data=proc_net_arp)):
        mac = get_mac_for_ip("192.168.1.1")
        assert mac is None

def test_get_mac_for_ip_file_not_found():
    with patch("builtins.open", side_effect=OSError("No such file or directory")):
        mac = get_mac_for_ip("192.168.1.1")
        assert mac is None

def test_get_mac_for_ip_malformed_line():
    proc_net_arp = "IP address       HW type     Flags       HW address            Mask     Device\n" \
                   "192.168.1.1\n"
    
    with patch("builtins.open", mock_open(read_data=proc_net_arp)):
        mac = get_mac_for_ip("192.168.1.1")
        assert mac is None
