#!/usr/bin/env python3
"""Renders a sample of the comment HTML the playbook posts, using representative data.
Reflects the free-sources-only build: Sentinel geodata + RDAP + Tor list + AbuseIPDB."""
import pathlib

TBL = "border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%"
TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap"
TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top"
H4 = "margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px"
CHIP = "display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#fff;margin-left:6px;background:"
YES = '<b style="color:#a4262c">Yes</b>'
TORYES = '<b style="color:#a4262c">Yes &mdash; known Tor exit node</b>'

CASES = [
    dict(
        ip="103.187.6.124", verdict="MEDIUM", colour="#986f0b",
        reason="Signals: 0 TI match(es) &middot; AbuseIPDB 0% &middot; VT malicious 0 &middot; Tor exit: no &middot; 2 workspace insight row(s)",
        geo=dict(org="Vetta Online Ltd", orgtype="hosting", city="Kekerengu", citycf="72",
                 country="New Zealand", countrycf="99", state="Marlborough", statecode="mbh", statecf="65",
                 continent="Oceania", region="oceania", lat="-41.9847", lon="174.0021",
                 asn="137409", carrier="gsl networks", routing="fixed"),
        rdap=dict(name="VETTA-NZ", handle="APNIC-103-187-6-0", start="103.187.6.0", end="103.187.6.255", type="ALLOCATED PORTABLE"),
        tor="No", hosting=YES, mobile="No",
        signin=dict(user="j.okafor@bfree.example", time="2026-08-30 20:37:20", app="Office 365 Exchange Online",
                    result="0 - Success", status="Unknown IP address", trusted="Unknown",
                    known="No - first observed in this window", cc="NZ",
                    trust="Azure AD joined", dev="LT-JOKAFOR-01", compliant="true", managed="true",
                    devid="7c1f9a2e-3b44-4d80-9a11-6f0e2c9d5a17",
                    os="Windows10", browser="Edge 145.0.0",
                    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0 OS/10.0.26100",
                    risk="medium", rstate="atRisk", rdetail="none", revents='["unfamiliarFeatures"]',
                    ca="success", authreq="multiFactorAuthentication"),
        rep=[("AbuseIPDB", "Confidence of abuse: <b>0%</b> &nbsp;|&nbsp; 0 report(s) from 0 reporter(s) &nbsp;|&nbsp; usage: Data Center/Web Hosting/Transit &nbsp;|&nbsp; domain: gslnetworks.com &nbsp;|&nbsp; Tor: false &nbsp;|&nbsp; last report: never")],
        rows=[("SigninLogs", '4 sign-ins, 1 user(s), 0 failed | ["j.okafor@bfree.example"]', "2026-08-30T20:37:20Z"),
              ("Prior alerts", '1 alert(s) in 30d | ["User Logging in from a new IP and unseen ASN"] | severity: ["Medium"]', "2026-08-30T20:37:20Z")],
    ),
    dict(
        ip="69.160.113.77", verdict="HIGH", colour="#a4262c",
        reason="Signals: 1 TI match(es) &middot; AbuseIPDB 68% &middot; VT malicious 0 &middot; Tor exit: yes &middot; 3 workspace insight row(s)",
        geo=dict(org="Cable &amp; Wireless Jamaica", orgtype="isp", city="Kingston", citycf="88",
                 country="Jamaica", countrycf="99", state="Saint Andrew", statecode="02", statecf="80",
                 continent="North America", region="caribbean", lat="17.9970", lon="-76.7936",
                 asn="30689", carrier="flow jamaica", routing="fixed"),
        rdap=dict(name="CWJAMAICA", handle="NET-69-160-96-0-1", start="69.160.96.0", end="69.160.127.255", type="ALLOCATION"),
        tor=TORYES, hosting="No", mobile="No",
        signin=dict(user="a.mensah@bfree.example", time="2026-08-31 03:14:52", app="Microsoft 365 Portal",
                    result="0 - Success", status="Unknown IP address", trusted="Unknown",
                    known="No - first observed in this window", cc="JM",
                    trust="Azure AD joined", dev="LT-AMENSAH-04", compliant="true", managed="true",
                    devid="b93d17c5-8e0a-4f21-9c76-2ad4e1f88b30",
                    os="Windows10", browser="Edge 145.0.0",
                    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0 OS/10.0.26100",
                    risk="high", rstate="atRisk", rdetail="none", revents='["unfamiliarFeatures","impossibleTravel"]',
                    ca="success", authreq="multiFactorAuthentication"),
        rep=[("AbuseIPDB", "Confidence of abuse: <b>68%</b> &nbsp;|&nbsp; 41 report(s) from 17 reporter(s) &nbsp;|&nbsp; usage: Fixed Line ISP &nbsp;|&nbsp; domain: flowjamaica.com &nbsp;|&nbsp; Tor: true &nbsp;|&nbsp; last report: 2026-08-29T22:08:11Z")],
        rows=[("Threat Intel", "TI match - Credential stuffing infrastructure | type: Botnet | confidence: 75 | feed: Defender TI", "2026-08-30T11:02:00Z"),
              ("SigninLogs", '2 sign-ins, 1 user(s), 1 failed | ["a.mensah@bfree.example"]', "2026-08-31T03:14:52Z"),
              ("OfficeActivity", '18 events | users: ["a.mensah@bfree.example"]', "2026-08-31T03:41:07Z")],
    ),
]

GREY = 'color:#605e5c'


def block(c):
    g, d, si = c["geo"], c["rdap"], c["signin"]
    h = ['<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">',
         '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">',
         f'IP enrichment &mdash; <code>{c["ip"]}</code>',
         f'<span style="{CHIP}{c["colour"]}">{c["verdict"]}</span></div>',
         f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;{GREY};margin-bottom:10px">{c["reason"]}</div>',
         f'<div style="{H4}"><b>Geolocation</b> <span style="font-weight:400;{GREY}">(Microsoft Sentinel enrichment API &mdash; confidence 0-100 where shown)</span></div><table style="{TBL}">',
         f'<tr><th style="{TH}">Organization</th><td style="{TD}">{g["org"]}</td><th style="{TH}">Organization type</th><td style="{TD}">{g["orgtype"]}</td></tr>',
         f'<tr><th style="{TH}">City</th><td style="{TD}">{g["city"]} <span style="{GREY}">(cf {g["citycf"]})</span></td><th style="{TH}">Country</th><td style="{TD}">{g["country"]} <span style="{GREY}">(cf {g["countrycf"]})</span></td></tr>',
         f'<tr><th style="{TH}">State</th><td style="{TD}">{g["state"]} <span style="{GREY}">({g["statecode"]}, cf {g["statecf"]})</span></td><th style="{TH}">Continent</th><td style="{TD}">{g["continent"]}</td></tr>',
         f'<tr><th style="{TH}">Region</th><td style="{TD}">{g["region"]}</td><th style="{TH}">Coordinates</th><td style="{TD}"><a href="#">{g["lat"]}, {g["lon"]}</a></td></tr></table>',
         f'<div style="{H4}"><b>Network / ASN</b></div><table style="{TBL}">',
         f'<tr><th style="{TH}">ASN</th><td style="{TD}">{g["asn"]}</td><th style="{TH}">Carrier</th><td style="{TD}">{g["carrier"]}</td></tr>',
         f'<tr><th style="{TH}">Routing type</th><td style="{TD}">{g["routing"]}</td><th style="{TH}">RIR network</th><td style="{TD}">{d["name"]} ({d["handle"]})</td></tr>',
         f'<tr><th style="{TH}">Range</th><td style="{TD}">{d["start"]} &ndash; {d["end"]}</td><th style="{TH}">Allocation</th><td style="{TD}">{d["type"]}</td></tr>',
         f'<tr><th style="{TH}">Tor exit node</th><td style="{TD}">{c["tor"]}</td><th style="{TH}">Hosting / datacentre</th><td style="{TD}">{c["hosting"]}</td></tr>',
         f'<tr><th style="{TH}">Mobile / wireless</th><td style="{TD}">{c["mobile"]}</td><th style="{TH}">Geo lookup</th><td style="{TD}">ok</td></tr></table>',
         f'<div style="{H4}"><b>Sign-in context</b> <span style="font-weight:400;{GREY}">(most recent sign-in from this IP)</span></div><table style="{TBL}">',
         f'<tr><th style="{TH}">User</th><td style="{TD}">{si["user"]}</td><th style="{TH}">Sign-in time (UTC)</th><td style="{TD}">{si["time"]}</td></tr>',
         f'<tr><th style="{TH}">Application</th><td style="{TD}">{si["app"]}</td><th style="{TH}">Result</th><td style="{TD}">{si["result"]}</td></tr>',
         f'<tr><th style="{TH}">IP address status</th><td style="{TD}"><b>{si["status"]}</b></td><th style="{TH}">IP trusted location</th><td style="{TD}">{si["trusted"]}</td></tr>',
         f'<tr><th style="{TH}">Known IP</th><td style="{TD}">{si["known"]}</td><th style="{TH}">Country code (sign-in)</th><td style="{TD}">{si["cc"]}</td></tr>',
         f'<tr><th style="{TH}">Is proxy / anonymiser</th><td style="{TD}">{c["tor"]}</td><th style="{TH}">Is hosting / datacentre</th><td style="{TD}">{c["hosting"]}</td></tr>',
         f'<tr><th style="{TH}">Device trust</th><td style="{TD}">{si["trust"]}</td><th style="{TH}">Device name</th><td style="{TD}">{si["dev"]}</td></tr>',
         f'<tr><th style="{TH}">Compliant / managed</th><td style="{TD}">{si["compliant"]} / {si["managed"]}</td><th style="{TH}">Device ID</th><td style="{TD}">{si["devid"]}</td></tr>',
         f'<tr><th style="{TH}">Operating system</th><td style="{TD}">{si["os"]}</td><th style="{TH}">Browser</th><td style="{TD}">{si["browser"]}</td></tr>',
         f'<tr><th style="{TH}">User agent</th><td style="{TD}" colspan="3"><code style="font-size:11px">{si["ua"]}</code></td></tr>',
         f'<tr><th style="{TH}">Sign-in risk</th><td style="{TD}">{si["risk"]} (state: {si["rstate"]}, detail: {si["rdetail"]})</td><th style="{TH}">Risk events</th><td style="{TD}">{si["revents"]}</td></tr>',
         f'<tr><th style="{TH}">Conditional Access</th><td style="{TD}">{si["ca"]}</td><th style="{TH}">Auth requirement</th><td style="{TD}">{si["authreq"]}</td></tr></table>',
         f'<div style="{H4}"><b>Reputation</b></div><table style="{TBL}">']
    for name, val in c["rep"]:
        h.append(f'<tr><th style="{TH}">{name}</th><td style="{TD}">{val}</td></tr>')
    h.append("</table>")
    h.append(f'<div style="{H4}"><b>Workspace insights &mdash; last 14 days</b></div><table style="{TBL}">')
    h.append(f'<tr><th style="{TH}">Source</th><th style="{TH}">Detail</th><th style="{TH}">Last seen (UTC)</th></tr>')
    for s, det, last in c["rows"]:
        h.append(f'<tr><td style="{TD}"><b>{s}</b></td><td style="{TD}">{det}</td><td style="{TD}">{last}</td></tr>')
    h.append("</table>")
    return "".join(h)


body = (f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;{GREY}">'
        "Automated IP enrichment &mdash; playbook <b>ErgoSOC-AU-IP-Enrichment</b> "
        "&middot; run 2026-08-31 09:12 UTC</div>") + "".join(block(c) for c in CASES)

page = ("<!doctype html><html><head><meta charset='utf-8'><title>Sentinel IP enrichment comment - preview</title>"
        "</head><body style='background:#faf9f8;margin:0;padding:24px'>"
        "<div style='max-width:1000px;margin:0 auto;background:#fff;padding:20px;border:1px solid #e1dfdd'>"
        f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#a19f9d;margin-bottom:12px'>"
        "PREVIEW &mdash; what the playbook writes into the incident Comments tab, using only sources that are "
        "free for business use. Two IPs shown: one medium (hosting/datacentre, unknown IP), one high "
        "(TI match + Tor exit + AbuseIPDB 68%).</div>"
        f"{body}</div></body></html>")

p = pathlib.Path(__file__).parent / "preview.html"
p.write_text(page, encoding="utf-8")
print("wrote", p, p.stat().st_size, "bytes")
