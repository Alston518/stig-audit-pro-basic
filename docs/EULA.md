# End User License Agreement

> Draft for legal review. Replace every bracketed item before distribution. This template is not legal advice and does not become an effective agreement until approved and issued by the Licensor.

**Product:** STIG Audit Pro

**Document version:** 1.0-draft

**Applies to product version:** 0.2.0 and compatible updates provided by Licensor

**Effective date:** [EFFECTIVE DATE]

**Licensor:** [FULL LEGAL ENTITY NAME], [ENTITY ADDRESS] ("Licensor")

This End User License Agreement ("Agreement") is a legal agreement between Licensor and the individual or legal entity that installs, accesses, or uses STIG Audit Pro ("Licensee"). If an individual accepts this Agreement for an organization, that individual represents that they have authority to bind the organization. By installing, accessing, or using the Software, Licensee agrees to this Agreement. If Licensee does not agree, Licensee must not install, access, or use the Software.

## 1. Definitions

"Administrator" means a person authorized by Licensee to operate the Software and access the systems selected for assessment.

"Documentation" means the user, administrator, command, security, and product documentation supplied with the Software.

"Software" means STIG Audit Pro, its bundled check packs, templates, documentation, and Licensor-provided updates, excluding Third-Party Materials.

"Target Device" means a Cisco IOS-XE device that Licensee has expressly selected for an audit.

"Third-Party Materials" means software, standards, benchmarks, trademarks, documentation, or other materials owned or maintained by third parties, including open-source dependencies and Security Technical Implementation Guide content.

## 2. License grant

Subject to this Agreement and any applicable order form, Licensor grants Licensee a limited, non-exclusive, non-transferable, non-sublicensable, revocable license to install and use the Software solely for Licensee's authorized internal security assessment, compliance-support, evidence-collection, and reporting activities during the applicable license term.

Licensee may make a reasonable number of backup copies solely for lawful archival and disaster-recovery purposes. All copies must retain applicable copyright, proprietary, and attribution notices. Feature availability and device limits may depend on a valid signed license issued by Licensor. Licensee will not bypass, disable, forge, or interfere with license-verification or feature-enforcement controls.

## 3. Authorized use and access

Licensee will use the Software only:

- on Target Devices owned by Licensee or for which Licensee has documented permission to perform the assessment;
- through accounts and network paths that Licensee is authorized to use;
- within approved maintenance windows, rules of engagement, access-control policies, and change-management processes; and
- in compliance with applicable law, regulation, contract, policy, and third-party rights.

Licensee is responsible for its Administrators, credentials, Target Device selection, site profiles, check packs, scan timing, imported files, licenses, and exported evidence.

## 4. Read-only Target Device boundary

The Software is an assessment and evidence tool, not a remediation or device-management tool.

For the unmodified Software and bundled check packs identified in the Documentation:

1. After SSH session establishment and, only when Licensee supplies an enable secret, an `enable` authentication transition into privileged EXEC mode, the live-scan path issues only the documented Cisco IOS-XE `show` commands and `terminal length 0`.
2. The optional `enable` transition does not enter configuration mode or change device configuration. `terminal length 0` changes pagination only for the active terminal session; it does not alter the running configuration, alter the startup configuration, or persist after the session ends.
3. The Software does not invoke configuration mode and contains no workflow that sends configuration, save, erase, reload, commit, or remediation commands to a Target Device.
4. The Software makes zero changes to a Target Device's running or startup configuration.
5. The Software does not automatically correct, harden, or otherwise modify a Target Device in response to a result.

The Software does create and modify its own local application data, including profiles, check definitions, device groups, imported STIG metadata, per-run command evidence, audit history, licenses, checklists, and reports. Those local application operations are not Target Device configuration changes.

Licensee may be able to edit or add check packs. Any command inventory introduced by Licensee, a third party, or a modified build is outside the bundled-command representation above. Licensee must review and authorize all such content before use. Modification of the Software or its check packs may invalidate the documented read-only boundary and is at Licensee's risk.

## 5. Findings and administrator decisions

The Software compares collected command output with check logic and profile data. Its results are informational assessment outputs and may include `NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed`, `Error`, or `Skipped`.

The Software does not make operational, risk-acceptance, compliance, authorization-to-operate, or remediation decisions. Results may contain false positives, false negatives, incomplete evidence, parser errors, outdated benchmark mappings, or conclusions affected by incorrect site profiles or check logic.

All action taken or not taken based on a scan is solely at the discretion and responsibility of Licensee's authorized Administrator and applicable system owner, security owner, change authority, or authorizing official. Before making any change, Licensee must independently validate the finding, determine applicability, assess operational impact, obtain required approvals, prepare backup and rollback procedures, and use an authorized tool or manual process outside the Software. Licensor is not responsible for configuration changes or other actions performed by Licensee or any third party in response to Software output.

## 6. Restrictions

Except where applicable law expressly prohibits a restriction, Licensee will not:

- use the Software to access or assess a system without authorization;
- use the Software to disrupt a network, evade access controls, or conduct offensive operations;
- represent a Software result as a certification, accreditation, authorization to operate, or guarantee of compliance or security;
- remove or obscure copyright, proprietary, attribution, or disclaimer notices;
- distribute, rent, lease, sublicense, sell, or provide the Software as a service to a third party except as expressly permitted in writing by Licensor;
- reverse engineer, decompile, or disassemble the Software, except to the limited extent such restriction is prohibited by law; or
- use modified or unreviewed check packs in a production environment without documented approval.

## 7. Credentials, device data, and evidence

Licensee retains ownership of its credentials, device data, configurations, evidence, reports, profiles, and other content processed by the Software ("Licensee Data"). Licensee authorizes the Software to process Licensee Data locally as necessary to provide the documented functions.

The Software is designed to keep SSH passwords and enable secrets in process memory for the active session and not deliberately write them to profiles, reports, manifests, or evidence storage. Command output, including `show running-config`, is retained as sensitive local per-run evidence and may contain credentials, keys, community strings, topology, access-control data, or other sensitive information. Version 0.2 records SHA-256 values for post-collection integrity verification but does not automatically redact output or establish collector identity or chain of custody. Licensee is responsible for access controls, storage location, retention, encryption, backup, transfer, disclosure, and secure disposal of Licensee Data.

The Software does not include vendor-operated telemetry or a Licensor cloud service in product version 0.2.0. Optional STIG-source features can connect to the DoD Cyber Exchange or to a URL selected by an Administrator. Live scans connect to Target Devices selected by an Administrator. Licensee is responsible for approving those connections.

## 8. STIG and third-party materials

STIG content and other Third-Party Materials remain subject to their applicable ownership, license, attribution, and use terms. The Software's ability to import, display, compare, or evaluate such content does not transfer ownership to Licensee or Licensor.

STIG Audit Pro is not an official product of, endorsed by, certified by, or affiliated with the United States Department of Defense, the Defense Information Systems Agency, Cisco Systems, Inc., or any other third-party standards or product owner, unless Licensor states otherwise in a separately signed writing. All third-party names and marks belong to their respective owners.

Third-party software components are governed by their applicable licenses. Where a third-party license conflicts with this Agreement as to that component, the third-party license controls for that component.

## 9. Ownership

As between Licensor and Licensee, Licensor and its licensors retain all right, title, and interest in and to the Software, Documentation, improvements, and derivative works, including all intellectual-property rights. No rights are granted except those expressly stated in this Agreement.

[CHOOSE AND COMPLETE: Feedback may be used by Licensor without restriction and without obligation to Licensee, provided it does not identify Licensee or disclose Licensee Confidential Information.]

## 10. Updates, support, and availability

Support, maintenance, updates, and service levels are provided only as stated in a separate written order form or support policy. Licensor may change or discontinue pilot features. Licensee is responsible for verifying check-pack, profile, parser, Software, and STIG-source versions before relying on a result.

## 11. Disclaimer of warranties

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE, DOCUMENTATION, CHECK LOGIC, AND RESULTS ARE PROVIDED "AS IS" AND "AS AVAILABLE." LICENSOR DISCLAIMS ALL EXPRESS, IMPLIED, AND STATUTORY WARRANTIES, INCLUDING WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS, SECURITY, AND ERROR-FREE OR UNINTERRUPTED OPERATION.

LICENSOR DOES NOT WARRANT THAT THE SOFTWARE WILL IDENTIFY EVERY VULNERABILITY OR MISCONFIGURATION, THAT EVERY FINDING IS CORRECT, THAT A TARGET DEVICE IS SECURE OR COMPLIANT, OR THAT USE OF THE SOFTWARE WILL SATISFY ANY AUDIT, CONTRACT, LAW, REGULATION, STIG, SECURITY REQUIREMENT GUIDE, OR AUTHORIZATION REQUIREMENT.

Some jurisdictions do not allow certain warranty exclusions. In that event, the exclusions apply only to the maximum extent permitted by applicable law.

## 12. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, LICENSOR AND ITS AFFILIATES, SUPPLIERS, AND LICENSORS WILL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES; LOSS OF PROFITS, REVENUE, DATA, USE, GOODWILL, OR BUSINESS OPPORTUNITY; BUSINESS INTERRUPTION; SECURITY INCIDENT; DEVICE OR NETWORK OUTAGE; OR COST OF SUBSTITUTE GOODS OR SERVICES, ARISING OUT OF OR RELATED TO THE SOFTWARE, DOCUMENTATION, OR RESULTS, EVEN IF ADVISED OF THE POSSIBILITY.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE AGGREGATE LIABILITY OF LICENSOR AND ITS AFFILIATES, SUPPLIERS, AND LICENSORS ARISING OUT OF OR RELATED TO THIS AGREEMENT WILL NOT EXCEED [LIABILITY CAP, FOR EXAMPLE: FEES PAID OR PAYABLE FOR THE SOFTWARE DURING THE TWELVE MONTHS BEFORE THE EVENT GIVING RISE TO LIABILITY].

The limitations in this section apply regardless of the theory of liability and even if a remedy fails of its essential purpose. They do not limit liability that cannot lawfully be limited.

## 13. Indemnification

[COUNSEL TO SELECT OR REMOVE: Licensee will defend, indemnify, and hold harmless Licensor and its affiliates, personnel, suppliers, and licensors from third-party claims and related losses arising from Licensee's unauthorized system access, unlawful use, modified check packs, violation of this Agreement, or remediation and configuration actions taken in response to Software results.]

## 14. Term and termination

This Agreement begins on acceptance and continues until terminated or until the applicable license term ends. Licensee may terminate by ceasing use and deleting all copies, subject to lawful retention obligations. Licensor may terminate this Agreement upon written notice if Licensee materially breaches it and does not cure the breach within [NUMBER] days after notice, or immediately if the breach creates a material security, legal, or intellectual-property risk.

Upon termination, the license ends and Licensee must stop using and delete the Software, except for archival copies required by law. Sections that by their nature should survive will survive, including ownership, restrictions, disclaimers, limitations of liability, and general terms.

## 15. Government use

If Licensee is a United States government entity or contractor, any procurement, data-rights, records, security, accessibility, sovereign-immunity, disputes, or other mandatory government terms must be stated in an applicable contract or addendum signed by authorized representatives. No click-through or shrink-wrap term overrides a mandatory term that cannot legally be waived.

## 16. General terms

This Agreement is governed by the laws of [STATE/COUNTRY], without regard to conflict-of-law rules. The parties consent to exclusive jurisdiction and venue in the courts located in [COUNTY, STATE/COUNTRY], except where prohibited by law.

Neither party may assign this Agreement without the other's prior written consent, except that Licensor may assign it in connection with a merger, reorganization, sale of substantially all relevant assets, or transfer to an affiliate. This Agreement, together with an applicable signed order form and incorporated policies, is the complete agreement regarding the Software and supersedes prior or contemporaneous communications on that subject. An amendment must be in writing and signed by authorized representatives, except Licensor may update Documentation for new Software versions without reducing an existing paid license grant. Waiver of one breach is not waiver of another. If a provision is unenforceable, it will be modified to the minimum extent necessary and the remainder will remain effective. Headings are for convenience only.

Notices to Licensor must be sent to [LEGAL NOTICE EMAIL AND POSTAL ADDRESS]. Operational support requests must be sent to [SUPPORT CONTACT].

## 17. Acknowledgment

LICENSEE ACKNOWLEDGES THAT IT HAS READ AND UNDERSTANDS THIS AGREEMENT, INCLUDING THE READ-ONLY TARGET DEVICE BOUNDARY AND THE REQUIREMENT THAT ALL REMEDIATION DECISIONS AND ACTIONS REMAIN WITH LICENSEE'S AUTHORIZED PERSONNEL.
