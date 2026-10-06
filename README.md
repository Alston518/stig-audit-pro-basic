# STIG Audit Pro Basic

## Download the Windows app

Open the [latest Windows release](https://github.com/Alston518/stig-audit-pro-basic/releases/tag/basic-windows-2026-10-05) and download **STIG_Audit_Basic_IOS_IOSXE_2026-10-05_Public_Windows.zip** from its **Assets** section. Extract the entire ZIP to a writable Windows x64 folder and double-click `START BASIC AUDIT.cmd`. The EXE and its required files are included; Python is not needed.

GitHub's **Code → Download ZIP** button downloads repository source, not the ready-to-run Windows app. Use the Release asset for installation.

This release supports IOS and IOS XE L2/NDM audits, TXT and CKL output, and current-run combined PDF, HTML, and CSV summaries. Free Basic audits one selected device per run. A signed offline license can enable larger batches.

## Before a live audit

The public ZIP contains example-only site profiles. Enter your own approved VLANs, management networks, server names and addresses, and supported software versions in `Application/data/profiles/base_iosxe_access.yaml` or `base_ios_switch_access.yaml`. The [check-by-check worksheet](docs/basic/README.md) explains all 121 checks, the exact YAML field for each site value, checks that need no input, and manual reviews.

The release page provides a SHA-256 file. After extraction, `VERIFY PACKAGE.ps1` checks the package files before you customize profiles. Choose the blank CKL template matching the platform and check family when exporting a checklist.

## Repository source

The source currently visible in this repository is an earlier development snapshot. The October Windows Release asset is the downloadable combined reporting build. The owner signing application, private keys, and issued customer licenses are not included in that public ZIP.
