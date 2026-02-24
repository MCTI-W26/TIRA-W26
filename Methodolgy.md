# Collection Methodology
## CIS*6530 Submission 2 — Malicious Payload Dataset

**University of Guelph** | Dr. Ali Dehghantanha | February 2026

---

## 1. Overview

This document describes the methodology used to collect, identify, attribute, and organize the malicious payload dataset for Submission 2 of CIS*6530. The goal was to assemble a **diverse, attributable, and safely curated** set of malware samples and other malicious payloads, each traceable to one of the 38 APT groups in the Project 5 group set.

The methodology follows established practices in academic malware research, with emphasis on **source diversity**, **attribution rigor**, **chain-of-custody documentation**, and **safe handling**. Where direct sample collection was not possible due to limited public availability of certain APT group samples, the methodology prioritizes comprehensive IOC documentation and verified hash references from published threat intelligence reports — a recognized practice in academic malware research.

---

## 2. Data Sources

### 2.1 Primary Sources: MalwareBazaar and VirusShare

**MalwareBazaar**
**URL:** https://bazaar.abuse.ch/
**Rationale:** MalwareBazaar is operated by the Swiss nonprofit abuse.ch, one of the most trusted names in community-driven threat intelligence. It provides SHA256 hashes and full sample metadata (file type, size, first seen date), malware family signatures contributed by the security community, tag-based search enabling APT-oriented queries, and a REST API allowing programmatic and reproducible collection.

API endpoints used:
- `get_info` — retrieve metadata for a specific hash
- `get_taginfo` — search for samples by malware family tag
- `get_file` — download a sample (zip, password: `infected`)

**VirusShare**
**URL:** https://virusshare.com/
**Rationale:** VirusShare was used extensively as a complementary primary source alongside MalwareBazaar. VirusShare provides access to a large curated corpus of malware samples submitted by researchers worldwide. It was particularly valuable for sourcing samples from APT groups that are underrepresented in MalwareBazaar, including several North Korean and Chinese threat actors. VirusShare's hash sets and torrent-based sample distribution enabled bulk collection of samples cross-referenced against known APT family signatures. Samples obtained via VirusShare were validated by cross-referencing their SHA256 hashes against VirusTotal and MalwareBazaar metadata before inclusion.

### 2.2 Threat Intelligence Reports and Academic Publications

The primary driver of hash collection was a systematic review of publicly available threat intelligence reports, academic papers, and security vendor whitepapers. These documents directly report SHA256 hashes, IOCs, and malware family attributions for each APT group, enabling precise and verifiable sample collection.

Key sources reviewed and referenced:

| Source | Type | Groups Covered |
|---|---|---|
| Mandiant APT Reports (mandiant.com/resources) | Vendor TI Reports | APT32, APT37, APT38, Lazarus |
| CrowdStrike Adversary Intelligence | Vendor TI Reports | Winnti, ZIRCONIUM, Darkhotel |
| Kaspersky GReAT Publications | Academic/Vendor | Equation, Carbanak, Duqu, Strider |
| Symantec Threat Intelligence | Vendor TI Reports | Thrip, Whitefly, Sowbug, Strider |
| Unit 42 (Palo Alto Networks) | Vendor TI Reports | Rancor, Higaisa, Tropic Trooper |
| CISA Advisories (cisa.gov) | Government | Lazarus, APT38, Kimsuky |
| US-CERT Alerts | Government | Kimsuky, Lazarus, HIDDEN COBRA |
| MITRE ATTACK Group Pages | Open Knowledge Base | All 38 groups |
| Recorded Future Threat Intel | Vendor TI Reports | PLATINUM, Lotus Blossom, Leviathan |
| NTT Security Research | Academic/Vendor | Bisonal, TA459, DragonOK |

Each report was reviewed for reported SHA256 or MD5 hashes of malware samples, named malware family associations with specific APT groups, IOCs including IP addresses, domains, registry keys, and mutex names, as well as campaign timelines and victimology.

### 2.3 Secondary Sample Sources

| Source | URL | Usage |
|---|---|---|
| Malpedia | malpedia.caad.fkie.fraunhofer.de | Curated malware encyclopedia; sample download and family verification |
| AlienVault OTX | otx.alienvault.com | IOC pulses, hash cross-reference, campaign correlation |
| Hybrid Analysis | hybrid-analysis.com | Behavioral report verification, file type confirmation |
| VirusTotal | virustotal.com | Hash lookup, AV engine confirmation, family signature consensus |
| VirusShare | virusshare.com | Bulk hash sets and sample download for underrepresented APT groups |
| OpenCTI | Institutional instance | APT relationship mapping, campaign and TTP correlation |

---

## 3. Collection Process

### 3.1 Phase 1: APT Group Research and Hash Identification

For each of the 38 assigned APT groups, a structured research process was followed:

1. **MITRE ATTACK review** — Each group's ATTACK page was reviewed to identify associated software, techniques, and campaigns
2. **Threat intelligence report review** — Published reports (listed in Section 2.2) were reviewed to identify SHA256 hashes, IOCs, and malware family names explicitly attributed to each group
3. **Hash extraction** — SHA256 and MD5 hashes were extracted from report appendices, STIX/TAXII feeds, and IOC tables
4. **MalwareBazaar and VirusShare lookup** — Each extracted hash was queried against both MalwareBazaar (`get_info` endpoint) and VirusShare to retrieve file metadata and verify availability across both platforms
5. **Cross-reference validation** — The returned signature and tags fields were validated against the original report attribution to confirm consistency

This process ensured that every sample in the dataset has a **documented provenance chain** from a named, published threat intelligence source through to a verifiable SHA256 hash in MalwareBazaar or VirusShare.

### 3.2 Phase 2: Tag-Based and Hash-Set Supplementary Collection

To improve coverage for groups with fewer directly reported hashes, a supplementary collection phase was conducted across both MalwareBazaar and VirusShare.

**MalwareBazaar tag search:** Each APT group's associated malware families were used as search tags via the `get_taginfo` endpoint to identify additional community-attributed samples. The tag-to-APT mapping was derived from MITRE ATTACK software associations, malware family aliases documented in published threat intelligence, and MalwareBazaar community tag conventions.

**VirusShare hash set mining:** VirusShare publishes regularly updated hash sets covering tens of millions of samples. These hash sets were filtered against known APT malware family signatures and cross-referenced with VirusTotal to identify samples attributable to specific threat actor groups. This approach was particularly productive for North Korean APT groups (Lazarus, Kimsuky, APT37, APT38) and Chinese APT groups (Winnti, BlackTech, Taidoor) where VirusShare's corpus complemented MalwareBazaar's coverage.

### 3.3 Phase 3: IOC Documentation for Unavailable Groups

For APT groups where no samples were publicly available in MalwareBazaar, VirusShare, or other open repositories (notably Threat Group-3390, APT18, DragonOK, Dust Storm, Lotus Blossom, PLATINUM, Rancor, Tropic Trooper, Sowbug, Whitefly, NEODYMIUM, and Strider), a dedicated IOC documentation approach was applied:

- Published IOC lists were compiled from MITRE ATTACK, vendor reports, and government advisories
- Detailed IOC tables for each affected group are provided in the README and in the `Indicators_of_Compromise/` folder, covering malware family names, C2 IP addresses, C2 domains, file hashes, and targeted sectors

This approach reflects real-world threat intelligence practice, where attribution evidence frequently exists in documented form before the actual sample becomes publicly accessible. IOC documentation at this level of detail supports detection rule development, threat hunting, and ML feature engineering even in the absence of raw sample files.

### 3.4 Phase 4: Organization and File Naming

All samples were organized into the two-folder structure:
- Files classified as PE executables, ELF binaries, DLLs, or shellcode → `Executable_Malware/`
- All other files (scripts, documents, LNKs, macros, IOC lists) → `Other_Payloads/`

Each file was renamed using the standardized convention:
```
<MITRE_ID>_<APT_Name>_<SHA256_first16chars>.<extension>.zip
```

All files were individually compressed with password `infected` following the MalwareBazaar and VirusShare convention for safe storage and transport.

A `master_hash_manifest.xlsx` was generated recording full provenance for every sample, including SHA256 hash, filename, MITRE ID, APT name, category, file type, malware family signature, and source URL.

---

## 4. Inclusion and Exclusion Criteria

### Inclusion Criteria

A sample was included in the dataset if it met **all** of the following:
- ✅ Has credible attribution to one of the 38 assigned APT groups, supported by a named published source
- ✅ Sourced from a publicly accessible, ethically operated threat intelligence repository
- ✅ Has a verifiable SHA256 hash enabling integrity verification
- ✅ Has sufficient metadata to record in the hash manifest

### Exclusion Criteria

A sample was excluded if any of the following applied:
- ❌ No credible APT attribution linkable to any of the 38 assigned groups
- ❌ Duplicate SHA256 hash already present in the dataset
- ❌ Sourced from unverifiable, criminal, or ethically questionable origins
- ❌ File corrupted or hash mismatch on integrity check

---

## 5. Validation

Attribution quality was validated through:

1. **Cross-source validation** — Attributions were checked against at least two independent sources (e.g., MITRE ATTACK + vendor report) before inclusion
2. **Hash integrity verification** — SHA256 hashes were verified against MalwareBazaar and VirusShare records on download
3. **File type verification** — File type classifications were cross-checked using MIME type data from MalwareBazaar, VirusShare, and VirusTotal for a random 10% subset
4. **VirusShare cross-reference** — Samples sourced from VirusShare were validated against VirusTotal's 70+ engine consensus to confirm malware family attribution before inclusion

---

*Methodology Document | CIS*6530 Submission 2 | University of Guelph | February 2026*
