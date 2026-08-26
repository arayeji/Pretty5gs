from apn_provisioner.imsi import imsi_to_semi_octets, netwpin_mac


def test_oma_worked_example():
    # 310170212226432 -> 39 01 71 20 21 22 46 23 (OMA spec worked example, 2.4)
    assert imsi_to_semi_octets("310170212226432").hex() == "3901712021224623"


def test_network_example():
    # 432129951539038 -> 49 23 21 99 15 35 09 83 (real subscriber, 2.4)
    assert imsi_to_semi_octets("432129951539038").hex() == "4923219915350983"


def test_even_length_padding():
    # even digit count -> even indicator (low nibble 1) and 0xF tail padding
    out = imsi_to_semi_octets("12345678")
    assert out[0] == (0x1 << 4) | 0x1  # digit1=1, even indicator
    assert out[-1] >> 4 == 0xF  # padded tail


def test_mac_is_uppercase_hex_40():
    mac = netwpin_mac("432129951539038", b"\x03\x0b\x6a\x00")
    assert len(mac) == 40
    assert mac == mac.upper()
    assert all(c in "0123456789ABCDEF" for c in mac)
