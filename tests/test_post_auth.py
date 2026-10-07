import ipaddress

from modules import post_auth


def test_broad_subnet_is_bounded_around_obtained_ip():
    bounded = post_auth._bounded_scan_subnet("10.0.0.0/8", "10.20.30.40", 1024)
    network = ipaddress.ip_network(bounded)
    assert network.num_addresses <= 1024
    assert ipaddress.ip_address("10.20.30.40") in network


def test_gateway_lookup_never_falls_back_to_other_default_route(monkeypatch):
    commands = []
    monkeypatch.setattr(
        post_auth, "run_subprocess",
        lambda cmd: (commands.append(cmd) or 0, "", ""),
    )
    assert post_auth._get_gateway_from_routes("eth0") is None
    assert commands == [["ip", "route", "show", "dev", "eth0"]]


def test_ipv6_gateway_lookup_is_scoped_to_interface(monkeypatch):
    commands = []
    monkeypatch.setattr(
        post_auth,
        "run_subprocess",
        lambda cmd: (commands.append(cmd) or (0, "default via fe80::1 proto ra\n", "")),
    )
    assert post_auth._get_gateway_from_routes("eth0", family=6) == "fe80::1"
    assert commands == [["ip", "-6", "route", "show", "dev", "eth0"]]


def test_ipv6_post_auth_uses_ndp_not_numeric_subnet_scan(monkeypatch):
    monkeypatch.setattr(post_auth, "get_iface_netmask", lambda *a: "64")
    monkeypatch.setattr(post_auth, "get_iface_ipv6s", lambda *a, **k: ["2001:db8::9"])
    monkeypatch.setattr(post_auth, "_get_gateway_from_routes", lambda *a, **k: "fe80::1")
    monkeypatch.setattr(post_auth, "_parse_dhcp_leases", lambda *a: {})
    monkeypatch.setattr(post_auth, "_read_resolv_conf", lambda: [])
    monkeypatch.setattr(post_auth, "_ndp_discover", lambda *a, **k: [("fe80::2", "00:11:22:33:44:55")])
    monkeypatch.setattr(post_auth, "lookup_oui", lambda mac: ("Vendor", False))
    monkeypatch.setattr(post_auth, "_tcp_port_scan", lambda *a, **k: [])
    monkeypatch.setattr(post_auth, "_probe_gateway", lambda *a, **k: ([], None))
    monkeypatch.setattr(post_auth, "_detect_nac_server", lambda *a, **k: (None, None))

    result = post_auth.run_post_auth("eth0", "2001:db8::9", port_scan=False)
    assert result.address_family == "ipv6"
    assert result.subnet == "2001:db8::/64"
    assert result.scanned_subnet == "2001:db8::/64"
    assert [entry.ip for entry in result.ipv6_neighbors] == ["fe80::2"]


def test_dhcpv6_lease_options_are_parsed(tmp_path):
    lease = tmp_path / "dhclient6.leases"
    lease.write_text(
        'lease6 {\n  option dhcp6.name-servers 2001:db8::53,2001:db8::54;\n'
        '  option dhcp6.domain-search "corp.example";\n}\n',
        encoding="utf-8",
    )
    options = post_auth._parse_lease_file(str(lease))
    assert options["dhcp6.name-servers"] == "2001:db8::53,2001:db8::54"
    assert options["dhcp6.domain-search"] == "corp.example"
