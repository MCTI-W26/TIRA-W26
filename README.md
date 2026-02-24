# CIS*6530 — Submission 2: Malicious Payload Dataset
## Cyber Threat Intelligence and Adversarial Risk Analysis
**University of Guelph** | Dr. Ali Dehghantanha

---

> ⚠️ **WARNING — READ BEFORE PROCEEDING** ⚠️
>
> This repository contains **real malware samples** collected for academic research purposes under the course CIS*6530. All files are **inert in their stored, zipped form** but may be **immediately dangerous if extracted and executed**.
>
> **DO NOT EXECUTE ANY FILE IN THIS REPOSITORY UNDER ANY CIRCUMSTANCES.**
>
> Access, handling, and analysis of these samples must be conducted **exclusively in an isolated, offline virtual machine environment** as described in the Safe Handling section below.

---

## Table of Contents

1. [Repository Structure](#repository-structure)
2. [APT Group Coverage](#apt-group-coverage)
3. [Indicators of Compromise — Groups Without Samples](#indicators-of-compromise--groups-without-samples)
4. [Safe Handling Requirements](#safe-handling-requirements)
5. [Collection Methodology](#collection-methodology)
6. [File Naming Convention](#file-naming-convention)
7. [Hash Manifest](#hash-manifest)
8. [Ethical Sourcing Statement](#ethical-sourcing-statement)

---

## Repository Structure

```
Submission2/
│
├── Executable_Malware/              # PE files, ELF binaries, DLLs, shellcode
│   ├── G0032_Lazarus_Group_<hash>.exe.zip
│   ├── G0094_Kimsuky_<hash>.dll.zip
│   └── ...
│
├── Other_Payloads/                  # Scripts, documents, macros, LNKs
│   ├── G0050_APT32_<hash>.docx.zip
│   ├── G0127_TA551_<hash>.js.zip
│   └── ...
│
├── Indicators_of_Compromise/        # IOC reports and threat intel documents
│   ├── IOC.pdf
│   ├── IOC.docx
│   └── ...
│
├── README.md                        # This file
├── master_hash_manifest.xlsx        # Full provenance table for all samples
└── methodology.md                   # Collection methodology and sourcing details
```

### Folder Definitions

| Folder | Contents |
|---|---|
| `Executable_Malware/` | Files that are directly executable: `.exe`, `.dll`, `.sys`, `.elf`, `.scr`, `.msi`, shellcode blobs |
| `Other_Payloads/` | Non-executable malicious artifacts: scripts (`.ps1`, `.vbs`, `.js`, `.bat`), malicious documents (`.doc`, `.xls`, `.pdf`), `.lnk` files |
| `Indicators_of_Compromise/` | IOC reference documents including file hashes, C2 domains, and URLs for all 38 APT groups |

---

## APT Group Coverage

| MITRE ID | Group Name | Country | Samples |
|---|---|---|---|
| G0062 | TA459 | China | 1 |
| G0027 | Threat Group-3390 | China | IOC Only |
| G0044 | Winnti Group | China | 4 |
| G0128 | ZIRCONIUM | China | 3 |
| G0026 | APT18 | China | IOC Only |
| G0098 | BlackTech | China | 5 |
| G0017 | DragonOK | China | IOC Only |
| G0031 | Dust Storm | China | IOC Only |
| G0065 | Leviathan | China | 3 |
| G0030 | Lotus Blossom | China | IOC Only |
| G0068 | PLATINUM | China | IOC Only |
| G0075 | Rancor | China | IOC Only |
| G0015 | Taidoor | China | 5 |
| G0076 | Thrip | China | — |
| G0081 | Tropic Trooper | China | IOC Only |
| G0050 | APT32 | Vietnam | 4 |
| G0054 | Sowbug | Unknown | IOC Only |
| G0127 | TA551 | Unknown | 8 |
| G0089 | The White Company | Unknown | — |
| G0107 | Whitefly | Unknown | IOC Only |
| G0112 | Windshift | Unknown | — |
| G0033 | Poseidon Group | Portugal | — |
| G0085 | FIN4 | Romania | — |
| G0099 | APT-C-36 | South America | 9 |
| G0012 | Darkhotel | South Korea | — |
| G0126 | Higaisa | South Korea | 6 |
| G0095 | Machete | Spain | 10 |
| G0055 | NEODYMIUM | Turkey | 1 |
| G0056 | PROMETHIUM | Turkey | 5 |
| G0008 | Carbanak | Ukraine | 6 |
| G0038 | Stealth Falcon | UAE | 5 |
| G0020 | Equation | United States | 3 |
| G0041 | Strider | United States | IOC Only |
| G0067 | APT37 | North Korea | 27 |
| G0082 | APT38 | North Korea | 7 |
| G0094 | Kimsuky | North Korea | 69 |
| G0032 | Lazarus Group | North Korea | 64 |
| G0086 | Stolen Pencil | North Korea | 2 |

> **IOC Only** — No sample files were publicly available for these groups at time of collection. Full IOC hashes and domains are documented below and in the `Indicators_of_Compromise/` folder.

---

## Indicators of Compromise — Groups Without Samples

### G0075 — Rancor (China)

**File Hashes**
| Hash |
|---|
| `0bb20a9570a9b1e3a72203951268ffe83af6dcae7342a790fe195a2ef109d855` |
| `c35609822e6239934606a99cb3dbc925f4768f0b0654d6a2adc35eca473c505d` |
| `a789a282e0d65a050cccae66c56632245af1c8a589ace2ca5ca79572289fd483` |
| `1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458` |
| `863a9199decf36895d5d7d148ce9fd622e825f393d7ebe7591b4d37ef3f5f677` |
| `22a5bd54f15f33f4218454e53679d7cfae32c03ddb6ec186fb5e6f8b7f7c098b` |
| `9f779d920443d50ef48d4abfa40b43f5cb2c4eb769205b973b115e04f3b978f5` |
| `bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e` |
| `6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31` |
| `b099c31515947f0e86eed0c26c76805b13ca2d47ecbdb61fd07917732e38ae78` |
| `15f4c0a589dff62200fd7c885f1e7aa8863b8efa91e23c020de271061f4918eb` |
| `0f102e66bc2df4d14dc493ba8b93a88f6b622c168e0c2b63d0ceb7589910999d` |
| `84607a2abfd64d61299b0313337e85dd371642e9654b12288c8a1fc7c8c1cf0a` |
| `a725abb8fe76939f0e0532978eacd7d4afb4459bb6797ec32a7a9f670778bd7e` |
| `82e1e296403be99129aced295e1c12fbb23f871c6fa2acafab9e08d9a728cb96` |
| `9996e108ade2ef3911d5d38e9f3c1deb0300aa0a82d33e36d376c6927e3ee5af` |

---

### G0026 — APT18 (China)

**File Hashes**
| Hash |
|---|
| `d0f79de7bd194c1843e7411c473e4288` |
| `e5414c5215c9305feeebbe0dbee43567` |
| `985eba97e12c3e5bce9221631fb66d68` |
| `8FFBB7A80EFA9EE79E996ABDE7A95CF8DC6F9A41F9026672A8DBD95539FEA82A` |
| `da3261c332e72e4c1641ca0de439af280e064b224d950817a11922a8078b11f1` |
| `930772d6af8f43f62ea78092914fa8d6b03e8e3360dd4678eec1a3dda17206ed` |
| `6852ba95720af64809995e04f4818517ca1bd650bc42ea86d9adfdb018d6b274` |
| `9200f80c08b21ebae065141f0367f9c88f8fed896b0b4af9ec30fc98c606129b` |
| `4d62caef1ca8f4f9aead7823c95228a52852a1145ca6aaa58ad8493e042aed16` |
| `1b341dab023de64598d80456349db146aafe9b9e2ec24490c7d0ac881cecc094` |
| `456fffc256422ad667ca023d694494881baed1496a3067485d56ecc8fefbfaeb` |

---

### G0031 — Dust Storm (China)

**File Hashes**
| Hash |
|---|
| `da3261c332e72e4c1641ca0de439af280e064b224d950817a11922a8078b11f1` |
| `930772d6af8f43f62ea78092914fa8d6b03e8e3360dd4678eec1a3dda17206ed` |
| `6852ba95720af64809995e04f4818517ca1bd650bc42ea86d9adfdb018d6b274` |
| `9200f80c08b21ebae065141f0367f9c88f8fed896b0b4af9ec30fc98c606129b` |
| `4d62caef1ca8f4f9aead7823c95228a52852a1145ca6aaa58ad8493e042aed16` |
| `1b341dab023de64598d80456349db146aafe9b9e2ec24490c7d0ac881cecc094` |
| `456fffc256422ad667ca023d694494881baed1496a3067485d56ecc8fefbfaeb` |
| `4241a9371023e7452475117ff1fcd672` |
| `62dab56bf1943b5e0c73ff2b2e41f876` |
| `63bd3f80387e3f2c7130bc3b36474c24` |
| `edca4f063161b25bfe0c90b378b9c19c` |
| `74ff3b246fde30bb3c14483279d4b003` |
| `12038957e3956bf8682362044ddccf42` |
| `38238f14d63d14075824cc9afd9a3b84` |
| `df9b9c2f1408ac440458196a9e690db6` |
| `2978c6cfff1754c85a4a22b6a72dc9e6` |
| `0b596b54e65ed5ab2c80b8bc259ca5dc` |

---

### G0062 — TA459 (China)

**File Hashes**
| Hash |
|---|
| `a64ea888d412fd406392985358a489955b0f7b27da70ff604e827df86d2ca2aa` |
| `bf4b88e42a406aa83def0942207c8358efb880b18928e41d60a2dc59a59973ba` |
| `868ee879ca843349bfa3d200f858654656ec3c8128113813cd7e481a37dcc61a` |
| `4601133e94c4bc74916a9d96a5bc27cc3125cdc0be7225b2c7d4047f8506b3aa` |
| `5fd61793d498a395861fa263e4438183a3c4e6f1e4f098ac6e97c9d0911327bf` |
| `b5c208e4fb8ba255883f771d384ca85566c7be8adcf5c87114a62efb53b73fda` |
| `ab4cbfb1468dd6b0f09f6e74ac7f0d31a001d396d8d03f01bceb2e7c917cf565` |
| `79bd109dc7c35f45b781978436a6c2b98a5df659d09dee658c2daa4f1984a04e` |

**C2 URLs / Domains**
| IOC |
|---|
| `hxxp://122.9.52[.]215/news/power.rtf` |
| `hxxp://122.9.52[.]215/news/power.ps1` |
| `hxxp://www.firesyst[.]net/info/net/sports/drag/cgi.exe` |
| `www.icekkk[.]net` |

---

### G0027 — Threat Group-3390 (China)

> No specific hashes in IOC document. Refer to published Kaspersky and Dell SecureWorks reports for associated PlugX, Gh0st RAT, and HttpBrowser indicators.

---

### G0065 — Leviathan (China)

**File Hashes (MD5)**
| Hash |
|---|
| `26a5a7e71a601be991073c78d513dee3` |
| `87c88f06a7464db2534bc78ec2b915de` |
| `6a9bc68c9bc5cefaf1880ae6ffb1d0ca` |
| `64454645a9a21510226ab29e01e76d39` |
| `e2175f91ce3da2e8d46b0639e941e13f` |
| `9f89f069466b8b5c9bf25c9374a4daf8` |
| `187d6f2ed2c80f805461d9119a5878ac` |
| `ed7178cec90ed21644e669378b3a97ec` |
| `5bf7560d0a638e34035f85cd3788e258` |
| `e02be0dc614523ddd7a28c9e9d500cff` |

---

### G0030 — Lotus Blossom (China)

**File Hashes (SHA256)**
| Hash |
|---|
| `072022b54085690001ff9ec546051b2f60564ffbf5b917ac1f5a0e3abe7254a5` |
| `0cc6285d4bfcb5de4ebe58a7eab9b8d25dfcfeb12676b0c084e8705e69f6f281` |
| `148145b9a2e3f3abdc6c2d3de340eabc82457be67fb44cfa400a5e7bd2f88760` |
| `2a4302e61015fdf5f65fbd456249bafe96455cd5cc8aefe075782365b9ae3076` |
| `3585a5cbbf1b8b3206d7280355194d5442ed997f61e061fd6938a93163c79507` |
| `37fe8efe828893042e4f1db7386d20fec55518a3587643f54d4c3ec82c35df6d` |
| `3c35514b27c57a46a5593dbbbfceddbc49979b20fddc14b68bf4f0ee965a7c59` |
| `3dd7b684024941d5ab26df6730d23087037535783e342ee98a3934cccddb8c3e` |
| `64c546439b6b2d930f5aced409844535cf13f5c6d24e0870ba9bc0cf354d8c11` |
| `79f9f25b15e88c47ce035f15dd88f18ecc11e1319ff6f88568fdd0d327ad7cc1` |
| `7fe67567a5de33166168357d663b85bd452d64a4340bdad29fe71588ad95bf6f` |
| `80a8a9a2e91ead0ae5884e823dca73ef9fce59ff96111c632902d6c04401a4fe` |
| `861d1307913d1c2dbf9c6db246f896c0238837c47e1e1132a44ece5498206ec2` |
| `8f7c74a9e1d04ff116e785f3234f80119d68ae0334fb6a5498f6d40eee189cf7` |
| `a462085549f9a1fdeff81ea8190a1f89351a83cf8f6d01ecb5f238541785d4b3` |
| `adb61560363fcda109ea077a6aaf66da530fcbbb5dbde9c5923a59385021a498` |
| `bcc99bc9c02e1e2068188e63bc1d7ebe308d0d12ce53632baa31ce992f06c34a` |
| `b631abbfbbc38dac7c59f2b0dd55623b5caa1eaead2fa62dc7e4f01b30184308` |
| `c4a7a9ff4380f6b4730e3126fdaf450c624c0b7f5e9158063a92529fa133eaf2` |
| `e4a460db653c8df4223ec466a0237943be5de0da92b04a3bf76053fa1401b19e` |
| `f7ea532becda13a1dcef37b4a7ca140c56796d1868867e82500e672a68d029e4` |
| `f969578a0e7fe90041d2275d59532f46dee63c6c193f723a13f4ded9d1525c6b` |
| `fea2f48f4471af9014f92026f3c1b203825bb95590e2a0985a3b57d6b598c3f` |

---

### G0068 — PLATINUM (China)

**File Hashes (SHA1)**
| Hash |
|---|
| `e9f900b5d01320ccd4990fd322a459d709d43e4b` |
| `9a4e82ba371cd2fedea0b889c879daee7a01e1b1` |
| `92a3ece981bb5e0a3ee4277f08236c1d38b54053` |
| `0bc08dca86bd95f43ccc78ef4b27d81f28b4b769` |
| `f4af574124e9020ef3d0a7be9f1e42c2261e97e6` |
| `1bdc1a0bc995c1beb363b11b71c14324be8577c9` |
| `2a33542038a85db4911d7b846573f6b251e16b2d` |
| `d6a795e839f51c1a5aeabf5c10664936ebbef8ea` |
| `f362feedc046899a78c4480c32dda4ea82a3e8c0` |
| `f751cdfaef99c6184f45a563f3d81ff1ada25565` |

---

### G0081 — Tropic Trooper (China)

**File Hashes (SHA256)**
| Hash |
|---|
| `1d128fd61c2c121d9f2e1628630833172427e5d486cdd4b6d567b7bdac13935e` |
| `01087051f41df7bb030256c97497f69bc5b5551829da81b8db3f46ba622d8a69` |
| `6e900e5b6dc4f21a004c5b5908c81f055db0d7026b3c5e105708586f85d3e334` |
| `49df4fec76a0ffaee5e4d933a734126c1a7b32d1c9cb5ab22a868e8bfc653245` |
| `b0f120b11f727f197353bc2c98d606ed08a06f14a1c012d3db6fe0a812df528a` |
| `d65f809f7684b28a6fa2d9397582f350318027999be3acf1241ff44d4df36a3a` |
| `85d32cb3ae046a38254b953a00b37bb87047ec435edb0ce359a867447ee30f8b` |
| `02281e26e89b61d84e2df66a0eeb729c5babd94607b1422505cd388843dd5456` |
| `fb9c9cbf6925de8c7b6ce8e7a8d5290e628be0b82a58f3e968426c0f734f38f6` |

**C2 Domains**
| Domain |
|---|
| `qpoe[.]com` |
| `wikaba[.]com` |
| `tibetnews[.]today` |
| `dns-stuff[.]com` |
| `2waky[.]com` |

---

### G0054 — Sowbug (Unknown)

**File Hashes (MD5)**
| Hash |
|---|
| `514f85ebb05cad9e004eee89dde2ed07` |
| `00d356a7cf9f67dd5bb8b2a88e289bc8` |
| `c1f65ddabcc1f23d9ba1600789eb581b` |
| `967d60c417d70a02030938a2ee8a0b74` |
| `4984e9e1a5d595c079cc490a22d67490` |
| `e4e1c98feac9356dbfcac1d8c362ab22` |

---

### G0017 — DragonOK (China)

**File Hashes & C2 Servers**
| IOC Type | Value |
|---|---|
| MD5 (First stage) | `46e55cdf507ef10b11d74dad6af8b94e` |
| MD5 (First stage) | `989d04ab23385260a402ce7b6751e60e` |
| MD5 (First stage) | `6de67d5bfe61fbdc2febfd289e9660c3` |
| MD5 (First stage) | `908d847fd39a285185b3f0e8dc874dad` |
| MD5 (Implant) | `81998ee8b8f8304d038e3cb5ff10b4d2` — MSSoap.DLL |
| C2 Domain | `http.jpaols[.]com` |
| C2 Domain | `facebook.pktmedia[.]com` |
| C2 Domain | `facebook.skyppee[.]com` |
| C2 Domain | `sslc.moafee[.]com` |
| C2 Domain | `butitistrun.blogdns[.]com` |
| C2 Domain | `ct.datangcun[.]com` |

---

### G0107 — Whitefly (Unknown)

**File Hashes**
| Hash |
|---|
| `eab0a521aa7cac62d98d78ef845a8319` |
| `a196dfe4ef7d422aadf1709b12511ae82cb96aad030422b00a9c91fb60a12f17` |
| `79bef92272c7d1c6236a03c26a0804cc` |
| `d784a12fec628860433c28caa353bb52923f39d072437393629039fa4b2ec8ad` |
| `394df628b3c8977661c8bebea593e148` |
| `6e874ac92c7061300b402dc616a1095fa7d13c8a18c8a3ea5b30ffa832a7372c` |
| `51862c3615e2f8a807b1d59f3aef3507` |
| `ed3cd71eaca603a00e4c0804dc34d84dc38c6c1e1c1f43af0568fb162c44c995` |
| `b4a7049b90503534d494970851bdda62` |
| `9d9a6337c486738edf4e5d1790c023ba172ce9b039df1b7b9720ed4c4c9ade90` |
| `93c9310f3984d96f53f226f5177918c4ca78b2070d5843f08d2cf351e8c239d5` |
| `263dc5a8121d20403beeeea452b6f33d51d41c6842d9d19919def1f1cb13226c` |
| `b2b2e900aa2e96ff44610032063012aa0435a47a5b416c384bd6e4e58a048ac9` |
| `dda22de8ad7d807cdac8c269b7e3b35a3021dcbff722b3d333f2a12d45d9908d` |
| `f562e9270098851dc716e3f17dbacc7f9e2f98f03ec5f1242b341baf1f7d544c` |
| `7de8b8b314f2d2fb54f8f8ad4bba435e8fc58b894b1680e5028c90c0a524ccde` |

---

### G0041 — Strider (United States)

**File Hashes (MD5)**
| Hash |
|---|
| `2ce818518ca5fd03cbacb26173aa60ce` |
| `f3499a9d9ce3de5dc10de3d7831d0938` |
| `0a870c900e6db25a0e0a65b8545656d4` |
| `2fd8bb121a048e7c9e29040f9a9a6eee` |
| `4cc1b23daaaac6bf94f99f309854ea10` |
| `2c4aeacd3f7b587c599c2c4b5c1475da` |
| `f821eb4be9840feaf77983eb7d55e5f6` |

**C2 Domains**
| Domain |
|---|
| `akamaihub[.]com` |
| `igdata[.]net` |
| `mozillacdn[.]com` |
| `msupdatecdn[.]com` |
| `sslverification[.]net` |

---

### G0055 — NEODYMIUM (Turkey)

**File Hashes**
| Hash |
|---|
| `21a3862dfe21d6b216359c6baa3d3c2beb50c7a3` |
| `0b16135d008f6952df0caca104449c33d736e5fc` |
| `0852aa6b8df78069d75fa2f09b53d4476cdd252b` |
| `05dbe59a7690e28ca295e0f939a0c1213cb42eb0` |
| `3c2c7ac8fddbc3ee25ce0f73f01e668855ccdb80` |
| `211a111586cb5914876adb929ccae736928d8363` |
| `c972bf5751438c99fe3e02ecacf6fa759388c40e` |
| `72722073f0adba1919dc31ffa26638555ad5867f` |
| `2fb49455d65ad8baf18e3c604cd1b992b7ebbefa` |
| `f41b999f41312f2a0fe4eaf08e90824f73e0e186` |
| `d8d54574a082162220c3c2f3d3f4c1b1bd4d6255` |
| `86580603f5e1d817af87e8bf3ba4dc4ea9e3069d` |
| `cb5d0d1d557a1266f77357a951358c78196e97ff` |
| `d75d12d250e7a36f9ef1173d630a0059b8ea5349` |
| `a77db6e89d604eabf29a6114a30345a705b05107` |
| `b32b0d52fff7c09c60bb64bc396dc7522a457399` |
| `ade19bde9716770bef84ce4414a45c0462c2eba2` |
| `e4d82ab117b86fd44c02ff3289976d15a9d9ced4` |
| `88cb78d99fa0275db8123c17a2bd3b3d58f541da` |
| `a248f9ad5d757d589a06a253dc46637f4128eea9` |

---

## Safe Handling Requirements

### Mandatory Environment

All analysis of files in this dataset **must** be performed in a controlled environment meeting the following specifications:

1. **Isolated Virtual Machine**
   - Host OS: Any (Windows, Linux, macOS)
   - Guest OS: Windows 10/11 or REMnux
   - Hypervisor: VMware Workstation, VirtualBox, or Hyper-V
   - **Network adapter: Host-Only or Disconnected**

2. **Snapshot Before Analysis**
   - Take a clean snapshot before extracting any sample
   - Revert to snapshot after each analysis session

3. **No Shared Folders**
   - Disable shared folders and clipboard sharing between host and guest

4. **Extraction Password**
   - All zip archives use password: `infected`
   - Extract only inside the isolated VM

5. **Antivirus**
   - Disable real-time AV inside analysis VM before extraction

---

## Collection Methodology

See `methodology.md` for full details. Summary:

- **Primary sources:** MalwareBazaar (bazaar.abuse.ch) and VirusShare
- **Secondary sources:** OpenCTI, Malpedia, VirusTotal, AlienVault OTX, Hybrid Analysis
- **Attribution method:** SHA256 hashes extracted from published threat intelligence reports, cross-referenced with MITRE ATTACK, MalwareBazaar, and VirusShare
- **Inclusion criteria:** Credible attribution to one of the 38 assigned APT groups
- **Exclusion criteria:** No attribution, duplicate hashes, or unverifiable origins

---

## File Naming Convention

```
<MITRE_ID>_<APT_Name>_<SHA256_first16chars>.<extension>.zip

Examples:
  G0032_Lazarus_Group_a1b2c3d4e5f67890.exe.zip
  G0094_Kimsuky_9f8e7d6c5b4a3210.ps1.zip
```

All files are individually compressed with password `infected`.

---

## Hash Manifest

`master_hash_manifest.xlsx` contains the complete provenance record for every sample:

| Column | Description |
|---|---|
| `sha256` | Full SHA256 hash |
| `filename` | Standardized filename |
| `mitre_id` | MITRE ATTACK group ID |
| `apt_name` | Group name |
| `category` | `Executable_Malware` or `Other_Payloads` |
| `file_type` | File type |
| `signature` | Malware family signature |
| `source_url` | Source URL |

---

## Ethical Sourcing Statement

All samples were collected from publicly accessible, community-operated threat intelligence platforms:

- **MalwareBazaar** (abuse.ch): Swiss nonprofit; samples submitted voluntarily by researchers worldwide
- **VirusShare**: Researcher-vetted platform providing curated malware samples for academic research
- **Malpedia** (Fraunhofer FKIE): German government research institute; curated malware encyclopedia
- **AlienVault OTX**: AT&T Cybersecurity crowdsourced threat intelligence platform
- **Hybrid Analysis** (CrowdStrike): Free behavioral analysis and sample access
- **VirusTotal**: Google's 70+ engine malware scanning and hash verification platform
- **MITRE ATTACK**: Primary attribution reference for all APT group mappings

No samples were obtained through unauthorized access, criminal markets, or live infection extraction. This dataset is used solely for CIS*6530 academic purposes at the University of Guelph.

---

*Dataset compiled for CIS*6530 — Submission 2 | University of Guelph | February 2026*
