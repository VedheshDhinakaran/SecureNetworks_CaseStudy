<?php
/* CS07 isolated lab only. Automates the README's interface/DHCP GUI steps.
 * Does not edit the repository policy or network objects. */
require_once 'config.inc';
require_once 'system.inc';
require_once 'util.inc';
require_once 'interfaces.inc';

if (PHP_OS_FAMILY !== 'BSD' || count($argv) !== 3 || $argv[1] !== '--apply') {
    fwrite(STDERR, "Usage on the CS07 OPNsense VM: php configure_interfaces.php --apply firewall_plan.json\n");
    exit(1);
}
$plan = json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
$expected = ['lan' => 'em1', 'opt1' => 'em2', 'opt2' => 'em3', 'opt3' => 'em4', 'opt4' => 'em5'];
foreach ($expected as $id => $device) {
    if (($plan['interfaces'][$id]['device'] ?? '') !== $device) {
        throw new RuntimeException('Unexpected interface mapping: ' . $id);
    }
}
// This is the single isolated firewall, with NAT on em0 and MGMT on em1.
$config['interfaces']['wan'] = ['if' => 'em0', 'descr' => 'WAN', 'enable' => '1', 'ipaddr' => 'dhcp'];
foreach ($plan['interfaces'] as $id => $data) {
    if (!filter_var($data['address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        throw new RuntimeException('Invalid IPv4 address in exported plan');
    }
    $config['interfaces'][$id] = ['if' => $data['device'], 'descr' => $data['description'],
        'enable' => '1', 'ipaddr' => $data['address'], 'subnet' => (string)$data['prefix']];
}
$config['system']['hostname'] = 'cs07-fw';
$config['system']['domain'] = 'sjv.lab';
$config['system']['timezone'] = 'Asia/Kolkata';
$config['system']['ssh']['enabled'] = 'enabled';
$config['system']['ssh']['permitrootlogin'] = 'permitrootlogin';
$publicKey = trim(file_get_contents('/root/.ssh/authorized_keys'));
if (!preg_match('/^ssh-ed25519 [A-Za-z0-9+\/=]+(?: .*)?$/', $publicKey)) {
    throw new RuntimeException('Install the single lab administration public key before applying');
}
foreach ($config['system']['user'] as &$user) {
    if (($user['name'] ?? '') === 'root') {
        $user['authorizedkeys'] = base64_encode($publicKey . "\n");
    }
}
unset($user);
$config['nat']['outbound']['mode'] = 'automatic';
if (!isset($config['dhcpd']) || !is_array($config['dhcpd'])) {
    $config['dhcpd'] = [];
}
$config['dhcpd']['opt4'] = ['enable' => '1',
    'range' => ['from' => $plan['vendor_dhcp'][0], 'to' => $plan['vendor_dhcp'][1]],
    'gateway' => $plan['interfaces']['opt4']['address'],
    'dnsserver' => [$plan['interfaces']['opt4']['address']]];
// The Part III loader requires empty legacy per-interface GUI tabs.
// Remove only the two factory LAN allow rules, preserving any custom rules.
$removed = 0;
if (isset($config['filter']['rule'])) {
    $config['filter']['rule'] = array_values(array_filter($config['filter']['rule'], function ($rule) use (&$removed) {
        if (in_array($rule['descr'] ?? '', ['Default allow LAN to any rule', 'Default allow LAN IPv6 to any rule'], true)) {
            $removed++;
            return false;
        }
        return true;
    }));
}
write_config('CHG20261027 CS07 Part II isolated lab interface and DHCP setup');
echo "Saved the README lab interfaces, automatic NAT and vendor DHCP range.\n";
echo "Removed {$removed} factory GUI allow rules; the Part III policy is unchanged.\n";
echo "Reload the firewall services before using the new interfaces.\n";
