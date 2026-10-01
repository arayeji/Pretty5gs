from apn_provisioner.imsi import imsi_to_semi_octets, netwpin_mac


def test_oma_worked_example():
    # 310170212226432 -> 39 01 71 20 21 22 46 23 (OMA spec worked example, 2.4)
    assert imsi_to_semi_octets("310170212226432").hex() == "3901712021224623"


def test_network_example():
    # 001010123456789 -> 09 10 10 10 32 54 76 98 (test PLMN 001-01)
    assert imsi_to_semi_octets("001010123456789").hex() == "0910101032547698"


def test_even_length_padding():
    # even digit count -> even indicator (low nibble 1) and 0xF tail padding
    out = imsi_to_semi_octets("12345678")
    assert out[0] == (0x1 << 4) | 0x1  # digit1=1, even indicator
    assert out[-1] >> 4 == 0xF  # padded tail


def test_mac_is_uppercase_hex_40():
    mac = netwpin_mac("001010123456789", b"\x03\x0b\x6a\x00")
    assert len(mac) == 40
    assert mac == mac.upper()
    assert all(c in "0123456789ABCDEF" for c in mac)
