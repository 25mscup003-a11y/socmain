package com.soc.agent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;

public class LocalFirewallVpnServiceTest {
    @Test
    public void whitelistMatchesIpv4AndCidrEntries() {
        Set<String> entries = new HashSet<>(Arrays.asList(
                "ip|203.0.113.8",
                "cidr|198.51.100.0/24",
                "ip|2001:db8::8",
                "cidr|2001:db8:abcd::/48"));

        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "203.0.113.8", "ip"));
        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "198.51.100.77", "ip"));
        assertFalse(LocalFirewallVpnService.whitelistMatches(entries, "198.51.101.77", "ip"));
        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "2001:db8::8", "ip"));
        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "2001:0db8:0:0:0:0:0:8", "ip"));
        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "2001:db8:abcd::42", "ip"));
        assertFalse(LocalFirewallVpnService.whitelistMatches(entries, "2001:db8:abce::42", "ip"));
    }

    @Test
    public void whitelistMatchesDomainAndSubdomainsOnly() {
        Set<String> entries = new HashSet<>(Arrays.asList("domain|example.com"));

        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "example.com", "domain"));
        assertTrue(LocalFirewallVpnService.whitelistMatches(entries, "api.example.com", "domain"));
        assertFalse(LocalFirewallVpnService.whitelistMatches(entries, "notexample.com", "domain"));
    }

    @Test
    public void isolationAlwaysUsesFullTunnel() {
        assertTrue(LocalFirewallVpnService.requiresFullTunnel(true, false));
        assertTrue(LocalFirewallVpnService.requiresFullTunnel(true, true));
        assertTrue(LocalFirewallVpnService.requiresFullTunnel(false, true));
        assertFalse(LocalFirewallVpnService.requiresFullTunnel(false, false));
    }
}
