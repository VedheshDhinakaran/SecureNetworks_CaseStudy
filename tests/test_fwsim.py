"""Part I simulator: the five stateless failures and the incident replay."""
from fwsim import incidents
from fwsim.engines import StatefulFirewall, StatelessFilter
from fwsim.nat import PatTable
from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

MODEL = ObjectModel.load()


def mini(rules):
    return Policy.from_dict({"defaults": {"review": "Q"}, "rules": rules}, MODEL)


R03_ONLY = [
    {"id": "R-03", "src": "Z_RADIOLOGY", "dst": "H_EMR_APP", "svc": "S_HTTPS", "action": "permit", "owner": "RAD", "req": "x"},
    {"id": "X-99", "src": "any", "dst": "any", "svc": "any", "action": "deny", "owner": "SEC", "req": "x"},
]


def test_stateless_drops_reply_without_reverse_rule():
    fw = StatelessFilter(mini(R03_ONLY))
    syn = Packet("192.168.40.100", "192.168.10.21", "tcp", 443)
    assert fw.process(syn).action == "permit"
    assert fw.process(syn.reply("SA")).action == "deny"          # direction failure


def test_stateful_admits_reply_and_rejects_unsolicited_ack():
    fw = StatefulFirewall(mini(R03_ONLY))
    syn = Packet("192.168.40.100", "192.168.10.21", "tcp", 443, sport=40000)
    assert fw.process(syn, 0).action == "permit"
    assert fw.process(syn.reply("SA"), 1).action == "permit"
    assert fw.process(Packet("192.168.40.100", "192.168.10.21", "tcp", 443, sport=40000, flags="A"), 2).action == "permit"
    # an ACK that belongs to no session (ACK scan) is dropped
    stray = Packet("192.168.10.21", "192.168.40.100", "tcp", 8080, sport=443, flags="A")
    assert fw.process(stray, 3).action == "deny"


def test_reverse_rule_abuse_stateless_vs_stateful():
    """E4 step 3: a 'reply' rule lets the server side open new sessions."""
    rules = R03_ONLY[:1] + [
        {"id": "REV", "src": "H_EMR_APP", "dst": "Z_RADIOLOGY", "svc": "any", "action": "permit", "owner": "IT", "req": "reverse"},
    ] + R03_ONLY[1:]
    syn_from_server = Packet("192.168.10.21", "192.168.40.100", "tcp", 8080, sport=443, flags="S")
    assert StatelessFilter(mini(rules)).process(syn_from_server).action == "permit"
    assert StatefulFirewall(mini(R03_ONLY)).process(syn_from_server).action == "deny"


def test_new_syn_cannot_reuse_closing_session():
    fw = StatefulFirewall(mini(R03_ONLY))
    syn = Packet("192.168.40.100", "192.168.10.21", "tcp", 443, sport=40000)
    assert fw.process(syn, 0).action == "permit"
    assert fw.process(syn.reply("SA"), 1).action == "permit"
    assert fw.process(Packet(syn.src, syn.dst, "tcp", syn.dport, syn.sport, "A"), 2).action == "permit"
    assert fw.process(Packet(syn.src, syn.dst, "tcp", syn.dport, syn.sport, "FA"), 3).action == "permit"
    assert fw.process(syn, 4).action == "deny"


def test_udp_pseudo_state_expires():
    rules = [{"id": "DV-01", "src": "Z_DEVICES", "dst": "H_DNS", "svc": "S_DNS", "action": "permit", "owner": "BIO", "req": "x"},
             R03_ONLY[1]]
    fw = StatefulFirewall(mini(rules))
    q = Packet("192.168.30.10", "192.168.10.53", "udp", 53, sport=5353)
    assert fw.process(q, 0).action == "permit"
    assert fw.process(q.reply(""), 5).action == "permit"
    assert fw.process(q.reply(""), 200).action == "deny"           # entry timed out


def test_app_id_blocks_ssh_on_443():
    pol = Policy.load(model=MODEL)
    syn = Packet("192.168.40.100", "192.168.10.21", "tcp", 443, sport=40000,
                 user_groups=("GRP_RADIOLOGISTS",))
    ssh = Packet("192.168.40.100", "192.168.10.21", "tcp", 443, sport=40000,
                 flags="PA", user_groups=("GRP_RADIOLOGISTS",), app="ssh")
    stateful = StatefulFirewall(pol)
    ngfw = StatefulFirewall(pol, ngfw=True)
    for fw in (stateful, ngfw):
        assert fw.process(syn, 0).action == "permit"
        assert fw.process(syn.reply("SA"), 1).action == "permit"
        assert fw.process(Packet(syn.src, syn.dst, "tcp", syn.dport, syn.sport, "A"), 2).action == "permit"
    assert stateful.process(ssh, 3).action == "permit"
    denied = ngfw.process(ssh, 3)
    assert denied.action == "deny" and denied.rule.id == "R-03"
    assert not ngfw.table


def test_pat_maps_reply_and_rejects_unsolicited():
    pat = PatTable()
    pub, port = pat.outbound("192.168.50.25", 50000, "93.184.216.34", 443)
    assert pub == "203.0.113.1"
    assert pat.inbound(port, "93.184.216.34", 443) == ("192.168.50.25", 50000)
    assert pat.inbound(port + 1, "93.184.216.34", 443) is None


def test_every_incident_case_behaves_as_designed():
    rows = incidents.run(verbose=False)
    checked = [r for r in rows if r[-1] is not None]
    bypassed = [r for r in rows if r[-1] is None]
    assert len(checked) == 17 and all(r[-1] for r in checked), [r for r in checked if not r[-1]]
    assert len(bypassed) == 1 and bypassed[0][0] == "F1"
    assert bypassed[0][3:5] == ("not tested", "access layer")
    case = next(c for c in incidents.CASES if c.ref == "F1" and not c.crosses_firewall)
    assert MODEL.zone_of(case.pkt.src) == MODEL.zone_of(case.pkt.dst) == "Z_DEVICES"
