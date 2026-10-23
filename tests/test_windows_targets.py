"""Windows target evidence collected from Kali; all fixtures are offline."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_target_analyzer", ROOT / "analyze-recon.py")
analyzer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyzer
SPEC.loader.exec_module(analyzer)


def nmap_xml(ports, scripts=(), address="10.10.10.10", args="nmap -sV --script smb-enum-shares 10.10.10.10"):
    root = ET.Element("nmaprun", args=args)
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "address", addr=address, addrtype="ipv4")
    container = ET.SubElement(host, "ports")
    for number, name, product, version, port_scripts in ports:
        port = ET.SubElement(container, "port", protocol="tcp", portid=str(number))
        ET.SubElement(port, "state", state="open")
        ET.SubElement(port, "service", name=name, product=product, version=version)
        for identifier, output in port_scripts:
            ET.SubElement(port, "script", id=identifier, output=output)
    hostscript = ET.SubElement(host, "hostscript")
    for identifier, output in scripts:
        ET.SubElement(hostscript, "script", id=identifier, output=output)
    return ET.tostring(root, encoding="unicode")


class WindowsTargetTests(unittest.TestCase):
    def load(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        contents = {".target.env": 'IP="10.10.10.10"\nHOST="dc.corp.test"\n',
                    "run-status.json": json.dumps({"status": "completed", "stages": []})}
        contents.update(files)
        for relative, text in contents.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        data = analyzer.load_recon(root, root)
        analyzer.run_vulnerability_intel(data, False, root / "unused-cache.json", 1, "", 8)
        return data

    def smb(self, output, product="Windows Server 2019", address="10.10.10.10", port=445):
        return nmap_xml([(port, "microsoft-ds", product, "", [])], [("smb-enum-shares", output),
                        ("smb-os-discovery", "OS: " + product + "\nDomain name: corp.test\nComputer name: DC")], address)

    def ldap(self, output, args=None, port=389):
        return nmap_xml([(port, "ldap", "Microsoft Windows Active Directory LDAP", "", [("ldap-search", output)])],
                        args=args or "nmap -sV --script ldap-search --script-args ldap.maxobjects=20,ldap.qfilter=users,ldap.attrib=sAMAccountName -p 389 10.10.10.10")

    def test_explicit_anonymous_smb_read_is_a_scoped_access_lead(self):
        output = "account_used: guest\n\\\\10.10.10.10\\Public:\n  Type: STYPE_DISKTREE\n  Anonymous access: READ\n  Current user access: READ\n"
        data = self.load({"enum/smb/nmap-smb-445.xml": self.smb(output)})
        route = analyzer.build_overview(data)["routes"][0]
        self.assertEqual(route["source"], "SERVICE-EVIDENCE")
        self.assertEqual(route["status"], "access-observed")
        self.assertEqual(route["target"], "smb://10.10.10.10:445/Public")
        self.assertEqual(route["context"]["domain"], "corp.test")
        self.assertEqual(route["context"]["hostname"], "DC")
        self.assertEqual(route["context"]["platform"], "Windows")
        self.assertFalse(data.vuln_matches)

    def test_denied_admin_or_share_names_only_are_not_read_access(self):
        examples = ["Public\n Anonymous access: <none>\n Current user access: READ\n",
                    "C$\n Anonymous access: READ/WRITE\n", "IPC$\n Anonymous access: READ\n",
                    "ERROR: NT_STATUS_ACCESS_DENIED"]
        for output in examples:
            with self.subTest(output=output):
                data = self.load({"enum/smb/nmap-smb-445.xml": self.smb(output),
                                  "enum/smb/smbclient-null-445.txt": "Public Disk Shared files\n"})
                self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_smbmap_readonly_requires_its_host_and_empty_credential_artifact(self):
        data = self.load({"enum/smb/smbmap-null.txt": "[+] IP: 10.10.10.10:445 Name: DC\nPublic READ ONLY Public files\nPrivate NO ACCESS\nC$ READ, WRITE\n"})
        routes = analyzer.build_overview(data)["routes"]
        self.assertEqual(len(routes), 1)
        self.assertTrue(routes[0]["target"].endswith("/Public"))
        data = self.load({"enum/smb/smbmap-user.txt": "[+] IP: 10.10.10.10:445\nPublic READ ONLY\n"})
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_multiple_readable_shares_are_grouped(self):
        data = self.load({"enum/smb/smbmap-null.txt": "[+] IP: 10.10.10.10:445\nPublic READ ONLY\nProjects READ ONLY\n"})
        routes = analyzer.build_overview(data)["routes"]
        self.assertEqual(len(routes), 1)
        self.assertEqual(len(routes[0]["inputs"]), 2)

    def test_anonymous_directory_objects_require_object_data_and_proven_invocation(self):
        output = "DC=corp,DC=test\n  dn: CN=sample,CN=Users,DC=corp,DC=test\n    sAMAccountName: sample\n"
        data = self.load({"enum/ldap/nmap-ldap-search.xml": self.ldap(output)})
        route = analyzer.build_overview(data)["routes"][0]
        self.assertEqual(route["title"], "Anonymous LDAP object access")
        self.assertEqual(route["context"]["domain"], "corp.test")
        self.assertIn("bounded anonymous query", route["next_test"])
        for args in ("", "nmap --script ldap-search,ldap-brute", "nmap --script ldap-search --script-args ldap.username=analyst,ldap.password=test", "nmap --script ldap-search --script-args-file private.txt"):
            xml = nmap_xml([(389, "ldap", "Microsoft Windows Active Directory LDAP", "", [("ldap-search", output)])], args=args)
            data = self.load({"enum/ldap/nmap-ldap-search.xml": xml})
            self.assertEqual(analyzer.build_overview(data)["routes"], [])
            self.assertTrue(any(row.status == "authentication-unknown" for row in data.service_observations))

    def test_rootdse_and_denied_search_are_not_anonymous_objects(self):
        for output in ("defaultNamingContext: DC=corp,DC=test\nnamingContexts: DC=corp,DC=test", "Operations error: successful bind must be completed", "dn:\nobjectClass: top"):
            data = self.load({"enum/ldap/nmap-ldap-search.xml": self.ldap(output)})
            self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_signing_is_a_low_confidence_conditional_lead(self):
        xml = nmap_xml([(139, "netbios-ssn", "Samba smbd", "4.17", [])], [("smb2-security-mode", "3.1.1:\n Message signing enabled but not required")])
        data = self.load({"enum/smb/nmap-smb-139.xml": xml})
        route = analyzer.build_overview(data)["routes"][0]
        self.assertEqual(route["target"], "smb://10.10.10.10:139")
        self.assertEqual(route["status"], "conditional-lead")
        self.assertEqual(route["confidence"], "low")
        self.assertIn("coercion", route["prerequisites"][0])
        self.assertIn("reachable", route["prerequisites"][0])
        self.assertEqual(route["context"]["platform"], "Samba")

    def test_only_ports_and_management_metadata_never_create_vulnerability_routes(self):
        data = self.load({"scans/tcp-services.txt": "Nmap scan report for 10.10.10.10\n3389/tcp open ms-wbt-server Microsoft Terminal Services\n5986/tcp open ssl/http Microsoft HTTPAPI httpd 2.0\n445/tcp open microsoft-ds\n",
                          "enum/ldap/namingcontexts-636.txt": "# Target: ldaps://10.10.10.10:636\nnamingContexts: DC=corp,DC=test\n"})
        self.assertEqual(analyzer.build_overview(data)["routes"], [])
        findings = analyzer.build_findings(data)
        self.assertFalse(any(row.confidence == "high" and any(token in row.title for token in ("WinRM", "RDP")) for row in findings))

    def test_samba_is_not_windows_and_protocol_overrides_brand(self):
        data = self.load({"scans/tcp-services.txt": "Nmap scan report for 10.10.10.10\n445/tcp open microsoft-ds Samba smbd 4.17\n88/tcp open kerberos-sec Samba 4.17\n389/tcp open ldap Samba 4.17\n"})
        self.assertNotIn("Windows", analyzer.detect_profile(data))
        self.assertEqual(analyzer.service_ports(data, "smb"), {445})
        self.assertEqual(analyzer.service_ports(data, "kerberos"), {88})
        self.assertEqual(analyzer.service_ports(data, "ldap"), {389})

    def test_windows_version_fingerprint_is_not_limited_to_server_2022(self):
        data = self.load({"enum/rdp/nmap-rdp.xml": nmap_xml([(3389, "ms-wbt-server", "Microsoft Terminal Services", "", [("rdp-ntlm-info", "Product_Version: 10.0.17763\nDNS_Computer_Name: dc.corp.test\nOS: Windows Server 2019")])])})
        self.assertIn("Windows", analyzer.detect_profile(data))
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_out_of_scope_host_and_unc_cannot_create_access_lead(self):
        output = "\\\\10.10.10.99\\Public:\n Anonymous access: READ\n"
        data = self.load({"enum/smb/nmap-smb-445.xml": self.smb(output),
                          "enum/smb/nmap-other.xml": self.smb("Public\n Anonymous access: READ\n", address="10.10.10.99"),
                          "enum/smb/smbmap-null.txt": "[+] IP: 10.10.10.99:445\nPublic READ ONLY\n"})
        self.assertEqual(analyzer.build_overview(data)["routes"], [])
        self.assertTrue(all(analyzer.scope_host(row.target) == "10.10.10.10" for row in data.service_observations))

    def test_confirmed_windows_nse_vulnerability_outweighs_access_leads(self):
        xml = self.smb("Public\n Anonymous access: READ\n")
        root = ET.fromstring(xml)
        ET.SubElement(root.find("host/hostscript"), "script", id="smb-vuln-ms17-010", output="VULNERABLE:\nState: VULNERABLE\nRisk factor: HIGH\nIDs: CVE:CVE-2017-0143")
        data = self.load({"enum/smb/nmap-smb-445.xml": ET.tostring(root, encoding="unicode")})
        routes = analyzer.build_overview(data)["routes"]
        self.assertEqual(routes[0]["source"], "NMAP-NSE")
        self.assertEqual(routes[0]["advisory_ids"], ["CVE-2017-0143"])
        self.assertEqual(routes[0]["target"], "tcp://10.10.10.10:445")
        self.assertEqual(routes[1]["status"], "access-observed")

    def test_sql_port_comes_from_service_and_not_6520_assumption(self):
        for sql_port in (1433, 1444):
            data = self.load({"scans/tcp-services.txt": f"Nmap scan report for 10.10.10.10\n{sql_port}/tcp open ms-sql-s Microsoft SQL Server 2019 15.0.2000\n6520/tcp open http nginx 1.24.0\n"})
            self.assertEqual(analyzer.service_ports(data, "mssql"), {sql_port})
            finding = next(row for row in analyzer.build_findings(data) if row.title.startswith("MSSQL"))
            self.assertIn(f"--port {sql_port}", " ".join(finding.commands))
            self.assertNotIn("6520", " ".join(finding.commands))

    def test_tls_only_winrm_uses_ssl_and_correct_port(self):
        data = self.load({"scans/tcp-services.txt": "Nmap scan report for 10.10.10.10\n5986/tcp open ssl/http Microsoft HTTPAPI httpd 2.0\n"})
        finding = next(row for row in analyzer.build_findings(data) if row.title.startswith("WinRM"))
        self.assertIn("-P 5986 -S", " ".join(finding.commands))
        self.assertFalse(analyzer.preferred_web_base(data).endswith(":5986"))

    def test_http_service_overrides_conventional_windows_ports(self):
        data = self.load({"scans/tcp-services.txt": "Nmap scan report for 10.10.10.10\n1433/tcp open http nginx 1.24.0\n3389/tcp open http nginx 1.24.0\n5985/tcp open http nginx 1.24.0\n"})
        for category in ("mssql", "rdp", "winrm"):
            self.assertFalse(analyzer.service_ports(data, category))
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_ldaps_only_and_smb139_profiles_do_not_invent_other_services(self):
        data = self.load({"scans/tcp-services.txt": "Nmap scan report for 10.10.10.10\n636/tcp open ssl/ldap Microsoft Windows Active Directory LDAP\n139/tcp open netbios-ssn Samba smbd 4.17\n"})
        self.assertIn("LDAP exposed", analyzer.detect_profile(data))
        self.assertIn("SMB exposed", analyzer.detect_profile(data))
        finding = next(row for row in analyzer.build_findings(data) if "Directory" in row.title)
        self.assertIn("ldaps://10.10.10.10:636", " ".join(finding.commands))
        self.assertNotIn("DNS, Kerberos, LDAP, and SMB are exposed", finding.detail)

    def test_iis_sql_versions_are_keyword_candidates_only(self):
        xml = nmap_xml([(443, "https", "Microsoft IIS httpd", "10.0", []),
                        (1444, "ms-sql-s", "Microsoft SQL Server 2019", "15.0.2000", [])])
        data = self.load({"scans/tcp-services.xml": xml})
        terms = analyzer.nvd_keyword_terms(data)
        self.assertIn("Microsoft IIS httpd 10.0", terms)
        self.assertIn("Microsoft SQL Server 2019 15.0.2000", terms)
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_nondefault_tls_ldap_and_smb_manual_commands_use_actual_transport(self):
        xml = self.ldap("dn: CN=sample,DC=corp,DC=test\n sAMAccountName: sample\n", port=20636)
        root = ET.fromstring(xml)
        root.find("host/ports/port/service").set("tunnel", "ssl")
        data = self.load({"enum/ldap/nmap-ldap-search.xml": ET.tostring(root, encoding="unicode"),
                          "enum/smb/nmap-smb-1445.xml": self.smb("Public\n Anonymous access: READ\n", port=1445),
                          "enum/smb/smbclient-null-1445.txt": "Public Disk Shared files\n"})
        directory = next(row for row in analyzer.build_findings(data) if "Directory" in row.title)
        self.assertIn("ldaps://10.10.10.10:20636", " ".join(directory.commands))
        shares = next(row for row in analyzer.build_findings(data) if "share names" in row.title)
        self.assertTrue(all("-p 1445" in command for command in shares.commands))
        ldap_route = next(row for row in analyzer.build_overview(data)["routes"] if "LDAP" in row["title"])
        self.assertEqual(ldap_route["target"], "ldaps://10.10.10.10:20636")

    def test_windows_overview_remains_three_routes_and_short(self):
        xml = self.smb("Public\n Anonymous access: READ\n")
        root = ET.fromstring(xml)
        ET.SubElement(root.find("host/hostscript"), "script", id="smb2-security-mode", output="Message signing enabled but not required")
        data = self.load({"enum/smb/nmap-smb-445.xml": ET.tostring(root, encoding="unicode"),
                          "enum/ldap/nmap-ldap-search.xml": self.ldap("dn: CN=sample,DC=corp,DC=test\n sAMAccountName: sample\n")})
        overview = analyzer.build_overview(data)
        self.assertEqual(len(overview["routes"]), 3)
        self.assertLessEqual(len(analyzer.render_overview(overview).split()), 250)


if __name__ == "__main__":
    unittest.main()
