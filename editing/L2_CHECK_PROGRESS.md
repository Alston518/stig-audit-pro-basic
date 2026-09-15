# IOS-XE L2 Check Validation Progress

Last updated: 2026-07-28

Status meanings:

- `[x]` Individually tested successfully against a live switch and added/confirmed in the master library.
- `[ ]` Still needs individual live testing.
- `[~]` Intentionally deferred with a documented temporary result.

Progress: **20 of 22 individually tested**

## Individual Checks

- [x] V-220649 — 802.1X/MAB on access ports and profile-defined RADIUS group membership
- [x] V-220650 — VTP is Off or a VTP password is configured
- [~] V-220651 — Always Open pending QoS implementation and later automation
- [ ] V-220655
- [x] V-220656 — BPDU Guard enabled on all physical access ports
- [x] V-220657 — Global STP Loop Guard enabled
- [x] V-220658 — Unknown unicast flood blocking on all physical access ports
- [x] V-220659 — DHCP snooping enabled globally and for profile-defined VLANs
- [x] V-220660 — IP Source Guard on all physical access ports
- [x] V-220661 — Dynamic ARP Inspection enabled for profile-defined VLANs
- [x] V-220662 — Storm Control on all physical access ports
- [x] V-220663 — IGMP and IPv6 MLD snooping not disabled globally or per VLAN
- [x] V-220664 — Rapid PVST or MST spanning-tree mode enabled
- [x] V-220665 — UDLD enabled
- [x] V-220666 — Trunk negotiation reports Off on every switchport
- [x] V-220667 — Disabled access ports use the unused VLAN, with 802.1X exemption
- [x] V-220668 — Default VLAN not assigned to host-facing ports
- [x] V-220669 — Default/profile VLANs pruned from trunks
- [x] V-220670 — VLAN 1 has no management IP address
- [x] V-220671 — Copper Ethernet ports statically configured as access ports
- [x] V-220672 — Physical trunks use an explicit non-default native VLAN
- [x] V-220673 — No physical switchports assigned to the profile-defined native VLAN

## Combined L2 Testing

- [ ] Run all completed checks together against a known-compliant switch
- [ ] Run all completed checks together against a switch with known findings
- [ ] Run the complete L2 library against multiple representative switches
- [ ] Review Open, Error, and Not_Reviewed results for false positives
- [ ] Confirm final L2 YAML validation and automated test suite
- [ ] Begin NDM check validation
