# IMAGE PARSER — Full Project Plan

---

## Overview

The goal is to parse forensic artifacts from an E01 image (mounted via Arsenal Image Mounter) into **two output formats** that together serve as the RAG knowledge base for LLM-based attack timeline reconstruction:

- `unified_artifacts.csv` — primary RAG source (structured, row-per-event, optimized for embedding)
- `unified_artifacts.md` — human-readable audit report (narrative format, natural chunk boundaries, also usable in RAG and thesis writeup)

You are building **one unified parser system** with **3 parser modules** that all feed into a single normalizer:

```
Registry Parser Module  ←── SAM, SECURITY, SOFTWARE, SYSTEM, HKCU
                             (also covers UserAssist, ShimCache,
                              Persistence Keys, Shellbags —
                              all registry-based, reuse same code)

EVTX Parser Module      ←── Security, System, Application logs

LNK Parser Module       ←── .lnk files only
```

---

## Unified CSV Schema

Every artifact, regardless of type, maps to this single schema:

| Column | Description |
|---|---|
| `timestamp` | ISO 8601 UTC (normalized from all sources) |
| `artifact_type` | e.g. `REGISTRY_SAM`, `EVTX_SECURITY`, `SHELLBAG` |
| `user` | Account/SID involved (NULL if system-level) |
| `event_description` | Human-readable summary of what happened |
| `source` | Hive path, EVTX channel, or file path |
| `raw_value` | The raw data (key value, Event ID, hex, etc.) |
| `severity` | `LOW / MEDIUM / HIGH / CRITICAL` (rule-based tagging) |
| `image_label` | `MALICIOUS` or `NORMAL` (from your two captures) |

> **Note:** The `image_label` column is critical — it lets the LLM/RAG distinguish baseline behavior from attack behavior during retrieval.

---

## Pipeline Architecture

```
E01 Image
    │
    ▼
Arsenal Image Mounter  ← mount as drive letter (e.g. D:\)
    │
    ▼
Python Extraction Layer
    ├── Registry Parser     → python-registry (pip)
    ├── EVTX Parser         → python-evtx or evtx (pip)
    ├── LNK Parser          → LnkParse3 (pip)
    └── Shellbags           → custom via python-registry
    │
    ▼
Normalizer  ← maps each artifact to the unified schema
    │
    ▼
Exporter
    ├── unified_artifacts.csv  → Primary RAG source (structured embedding)
    └── unified_artifacts.md   → Human-readable report (narrative RAG + thesis)
```

---

## Module Breakdown

### Module 1 — Registry Parser

Covers ~70% of all artifacts. UserAssist, ShimCache, Persistence Keys, and Shellbags are **not separate parsers** — they are specific key targets within the same hive files.

| Sub-artifact | Hive | What to Extract |
|---|---|---|
| SAM | `SAM` | User accounts, RIDs, last login |
| SECURITY | `SECURITY` | Audit policy, LSA secrets |
| SOFTWARE | `SOFTWARE` | Installed apps, OS info, Run keys |
| SYSTEM | `SYSTEM` | Services, timezone, network config |
| HKCU | `NTUSER.DAT` | Per-user Run keys, typed paths |
| UserAssist | `NTUSER.DAT` | GUI program execution history |
| AppCompatCache (ShimCache) | `SYSTEM` | Program execution, timestamps |
| System Persistence Keys | `NTUSER.DAT` / `SOFTWARE` | Run, RunOnce, Services, Scheduled Tasks |
| Shellbags | `NTUSER.DAT` / `UsrClass.dat` | Folder access history |

**Library:** `python-registry`

---

### Module 2 — EVTX Parser

| Log | Key Event IDs to Flag |
|---|---|
| Security | 4624/4625 (logon/failed logon), 4720 (account created), 4688 (process created), 1102 (log cleared) |
| System | 7045 (new service installed), 6005/6006 (boot/shutdown) |
| Application | 1000 (application crash), custom application errors |

**Library:** `python-evtx`

---

### Module 3 — LNK Parser

| Artifact | What to Extract |
|---|---|
| `.lnk` files | Recently accessed files, target paths, timestamps |

**Library:** `LnkParse3`

---

## Normalizer Logic

Each parser outputs a Python dict that maps to the unified schema. All modules write to the same list → one `pandas` DataFrame → exported as both `unified_artifacts.csv` and `unified_artifacts.md`.

**Example — Registry SAM entry:**
```python
{
  "timestamp": "2025-06-01T10:23:00Z",
  "artifact_type": "REGISTRY_SAM",
  "user": "hacker_account",
  "event_description": "New local user account created: hacker_account (RID 1005)",
  "source": "SAM\\Domains\\Account\\Users",
  "raw_value": "RID=1005, Flags=0x14",
  "severity": "HIGH",
  "image_label": "MALICIOUS"
}
```

**How the same entry looks in the MD output:**
```markdown
## REGISTRY_SAM | 2025-06-01T10:23:00Z | HIGH
**User:** hacker_account
**Description:** New local user account created: hacker_account (RID 1005)
**Source:** SAM\Domains\Account\Users
**Raw Value:** RID=1005, Flags=0x14
**Image:** MALICIOUS

---
```

Each artifact block in the MD is separated by `---`, which acts as a natural **chunk boundary** for RAG.

---

## RAG Chunking Strategy (to finalize later)

**Recommendation:** Use fine-grained rows (each row = one chunk) but add a `session_window` column — a computed 5-minute bucket ID.

This gives flexibility:
- Embed **per-row** for precision retrieval
- Group by **`session_window`** for narrative timeline reconstruction

Decide at RAG time, not during parsing.

---

## Folder Structure

```
image-parser/
├── main.py                      # orchestrator
├── mounter/
│   └── arsenal_helper.py        # drive letter detection post-mount
├── parsers/
│   ├── registry/
│   │   ├── sam.py
│   │   ├── security.py
│   │   ├── software.py
│   │   ├── system.py
│   │   ├── hkcu.py
│   │   ├── userassist.py
│   │   ├── shimcache.py
│   │   ├── persistence.py
│   │   └── shellbags.py
│   ├── evtx/
│   │   ├── security_log.py
│   │   ├── system_log.py
│   │   └── application_log.py
│   └── lnk/
│       └── lnk_files.py
├── normalizer.py                # maps all parser output → unified schema
├── exporter.py                  # exports to both CSV and MD
└── output/
    ├── unified_artifacts.csv    # primary RAG source
    └── unified_artifacts.md     # human-readable report + secondary RAG source
```

---

## Recommended Python Libraries

| Library | Purpose |
|---|---|
| `python-registry` | All registry hive parsing |
| `python-evtx` | EVTX log parsing |
| `LnkParse3` | `.lnk` file parsing |
| `pandas` | Normalization + CSV export |
| `markdown` (built-in string formatting) | MD report generation (no extra library needed) |

---

## Output Format Comparison

| | CSV | MD |
|---|---|---|
| RAG chunking | ✅ Row = natural chunk | ✅ `---` separator = natural chunk |
| LLM readability | ✅ Structured | ✅ Very readable |
| Token efficiency | ✅ Compact | ✅ Clean |
| Human readability | ⚠️ Hard to skim | ✅ Easy to read |
| Embedding quality | ✅ Good | ✅ Good |
| Thesis writeup use | ⚠️ Not suitable | ✅ Ready to include |

**Both files are generated from the same normalizer output — no extra parsing cost.**

---

## Build Order

1. **Scaffold** folder structure + unified schema as a dataclass/dict template
2. **Module 1 — Registry parsers** (covers ~70% of artifact list)
3. **Module 2 — EVTX parsers**
4. **Module 3 — LNK parser**
5. **Normalizer + Exporter** — wire everything together, output both CSV and MD
6. **Test on both images** (malicious vs normal), verify `image_label` is correct
7. **Hand off to RAG pipeline** — use CSV for embedding, MD for narrative chunking

---

## Next Step

Start with **Module 1 — Registry Parser**, beginning with the SAM hive and the unified schema dataclass.
