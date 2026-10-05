# IPS country blocking

The IPS workspace has a **Block Country** tab beside Blocklist. Managers can create, edit, disable and delete country rules. Each rule selects one country, inbound/outbound/both directions, and the entire company, a department or an individual system. Add separate rules for additional countries or targets.

Company rules automatically cover all current and future departments and systems in that company. Department rules automatically cover newly enrolled systems. System rules follow the selected system when it changes department. Company rules require a manager with access to the entire company; department-scoped users can view inherited company rules but cannot modify them. Counts reflect the systems visible to the viewer. Company and department access checks apply to reads and writes; an agent receives only its own effective policy.

## Enforcement

Desktop/server release **0.1.11** includes country blocking. Updated agents reconcile the policy delivered by the authenticated heartbeat, normally every 60 seconds. Large IP lists are downloaded separately through the signed `/api/agent/country-block-policy` endpoint. IPdeny IPv4 and IPv6 country allocation lists are cached in MongoDB for 24 hours. Both feeds must be available and valid before a new policy is applied.

- Linux uses atomic nftables sets in the dedicated `inet soc_country_block` table. nftables and administrative privileges are required, including on hosts using UFW.
- Windows uses chunked Windows Defender Firewall rules in the `AJNAT Country Block` group. All firewall profiles must be enabled. Replacement rules are installed before previous country rules are removed.
- macOS uses the dedicated `com.soc.agent/country-block` PF anchor under the installed SOC anchor. Existing PF states may continue until they expire; the rules block new matching traffic.
- Phone and Solaris agents are unsupported. They remain visible in the System dropdown with a disabled “Country blocking unsupported” option, so department device counts match the inventory without suggesting enforcement is available.

Inbound matches remote source addresses; outbound matches remote destination addresses. The rules cover local host traffic, rather than traffic forwarded through a router. IPv4 and IPv6 SOC management server addresses are excluded so policy removal remains possible. Overlapping company/department/system rules are combined: disabling one rule does not cancel another matching rule or other IPS blocks.

Country membership follows public IP allocation data. VPN and proxy traffic is classified by its exit IP. This is country-range blocking, not proof of a person's physical location.

## IP and domain country checks

**Check IP / domain country** uses the existing `IPINFO_TOKEN` from `backend/.env`. The backend sends it to IPinfo Lite in an Authorization header; it is never included in browser responses or URLs. The authenticated `GET /api/ips/country-blocks/lookup?target=example.com` endpoint accepts a single IP or domain name, without a URL path or port.

IP lookups use IPinfo's country database. Domains are resolved through the backend's DNS resolver for both A and AAAA records, then each public address is checked separately. A domain can return multiple countries; its suffix and registrant are not used to infer its traffic's country. Results include provider, address family, DNS TTL and the time of the IPinfo observation. CDN/anycast routing, VPN exit IPs and the resolver location can affect the answer.

Private/reserved IPs have no public country. Missing DNS records, DNS failures, missing tokens, rate limits and unavailable country data are displayed explicitly. DNS and API calls have timeouts. Checks are capped at 16 unique addresses with an explicit partial-results notice. IPinfo results are cached for 30 minutes with a bounded cache; a repeated result keeps its original observation timestamp.

This check does not establish whether traffic is blocked. Country-wide firewall enforcement still uses IPdeny IPv4/IPv6 ranges, which may disagree with IPinfo. It does not call IPinfo for every packet. Likewise, a country lookup does not establish that an IP or domain is safe or malicious; threat-reputation checks are separate.

Existing IP enrichment now uses the same IPinfo client and no longer returns hardcoded data for specific public IPs. Its optional city/location and privacy supplements remain ip-api.com and proxycheck.io. If IPinfo fails, that enrichment can use ip-api.com as a clearly labeled country fallback. The dedicated country checker uses only IPinfo and displays unavailable when it cannot obtain a country. Missing ASN ranges, domain counts, anycast flags and abuse contacts are no longer invented.

## Synchronization and recovery

Rules are saved as desired policy. **Applied** requires a recent endpoint report for the exact current policy revision. Pending, offline, failed and unsupported systems remain visible separately. Existing agent installations must be updated with the new agent source; deploying this dashboard/backend change alone does not upgrade endpoints.

The synchronization table separates **Connection** from **Policy sync** and displays the last heartbeat. Connection uses the same ten-minute heartbeat window, active status and installed-agent check as the Systems inventory. An online agent without a current country-policy report shows **Online / Pending sync**. A new system awaiting its first heartbeat shows **Not connected yet**. The country-policy acknowledgement must still be fresh within three minutes to show Applied; the longer connection window does not imply successful enforcement.

Agents retain the last successful policy on disk and restore it after restart. Failed downloads and failed Linux firewall transactions retain existing rules. A failed Windows replacement can leave additional staging blocks until the next successful reconciliation; it is reported as failed. Disabling or deleting a rule removes its contribution when the agent next synchronizes; offline agents keep their last applied blocks. Removing the last rule does not require a country feed download.

API paths under `/api/ips`: `GET /countries`, `GET /country-blocks`, `GET /country-blocks/summary`, `POST /country-blocks`, `PATCH /country-blocks/:id`, `DELETE /country-blocks/:id`.

## Validation

Run `node --test test/countryBlock.test.js test/systemPresence.test.js test/ipCountryLookup.test.js` from `backend`, and `PYTHONPATH=backend/soc-agent python3 -m unittest discover -s backend/soc-agent/tests -p test_country_block.py` from the workspace root. These cover targeting, authorization, revision acknowledgement, feed validation, directional firewall generation, overlapping rules, management exclusions, removal, IPinfo provenance, DNS resolution and failure recovery. Native Windows/macOS firewall execution requires validation on those operating systems.
