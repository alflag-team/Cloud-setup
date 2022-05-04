def apply_rules(iptables, target_rules):
    for rule in target_rules:
        index = find_rule(iptables, rule[3])
        if rule[0] == "ADD":
            iptables = add_rule(iptables, index, rule[1], rules[2])
    return iptables


def find_rule(iptables, target_rule):
    index = iptables.index(target_rule)
    return index


def add_rule(iptables, index, protocol, port):
    if protocol == "TCP":
        rule = "-A INPUT -p tcp -m state --state NEW -m tcp --dport " + port + " -j ACCEPT"
    elif protocol == "UDP":
        rule = "-A INPUT -p udp -m state --state NEW -m udp --dport " + port + " -j ACCEPT"
    iptables.insert(index + 1, rule)
    return iptables


def load_iptables(path):
    with open(path) as f:
        iptables = f.read().splitlines()
    return iptables


def main():
    path = "/etc/iptables/rules.v4"
    target_rules = [
        ["ADD", "TCP", "2377", "-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT"],
        ["ADD", "TCP", "7946", "-A INPUT -p tcp -m state --state NEW -m tcp --dport 2377 -j ACCEPT"],
        ["ADD", "UDP", "7946", "-A INPUT -p tcp -m state --state NEW -m tcp --dport 7946 -j ACCEPT"],
        ["ADD", "TCP", "4789", "-A INPUT -p udp -m state --state NEW -m udp --dport 7946 -j ACCEPT"],
        ["ADD", "UDP", "4789", "-A INPUT -p tcp -m state --state NEW -m tcp --dport 4789 -j ACCEPT"]
    ]
    iptables = load_iptables(path)
    apply_rules(iptables, target_rules)


if __name__ == '__main__':
    main()
