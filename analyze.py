#!/usr/bin/env python3
"""
Analysis pipeline for the Trivy vs Grype comparison.

Steps
1. Load the raw JSON output of both scanners (results/trivy, results/grype).
2. Build a reference set ("ground truth") for OS package findings by checking each
   finding against the distribution security trackers (Debian, Ubuntu, Alpine).
3. Compute precision, recall, false positives and false negatives per tool.
4. Explain disagreements (findings reported by only one tool).
5. Join findings with EPSS scores and the CISA KEV catalog.
6. Write CSV tables, a plain markdown summary and charts to out/.

Usage:  python3 analyze.py [--results results] [--data data] [--out out]
Needs:  pandas, matplotlib, and internet access on the first run (data is cached in data/).
"""
import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import pandas as pd

UA = {"User-Agent": "trivy-vs-grype-student-project"}
DEBIAN_CODENAMES = {"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie"}
UBUNTU_CODENAMES = {"18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]


# ---------------------------------------------------------------- downloads
def fetch(url, dest, binary=True):
    dest = Path(dest)
    if dest.exists() and dest.stat().st_size > 0:
        return dest.read_bytes() if binary else dest.read_text()
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    dest.write_bytes(data)
    return data if binary else data.decode()


def try_fetch(url, dest):
    try:
        return fetch(url, dest)
    except Exception as exc:  # network problem, 404, etc.
        print(f"  could not download {url}: {exc}", file=sys.stderr)
        return None


def load_kev(data):
    raw = try_fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        Path(data) / "kev.json",
    )
    if not raw:
        return set()
    return {v["cveID"] for v in json.loads(raw).get("vulnerabilities", [])}


def load_epss(data):
    dest = Path(data) / "epss.csv.gz"
    raw = try_fetch("https://epss.cyentia.com/epss_scores-current.csv.gz", dest)
    if not raw:
        raw = try_fetch("https://epss.empiricalsecurity.io/epss_scores-current.csv.gz", dest)
    if not raw:
        return {}
    text = gzip.decompress(raw).decode()
    lines = [l for l in text.splitlines() if not l.startswith("#")]
    out = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        out[row["cve"]] = float(row["epss"])
    return out


def load_debian(data):
    raw = try_fetch("https://security-tracker.debian.org/tracker/data/json", Path(data) / "debian.json")
    return json.loads(raw) if raw else {}


_alpine_cache = {}


def alpine_secfixes(data, version):
    """{package: {fixed_version: [CVE,...]}} for an Alpine release such as 3.12."""
    if version in _alpine_cache:
        return _alpine_cache[version]
    out = {}
    for repo in ("main", "community"):
        raw = try_fetch(f"https://secdb.alpinelinux.org/v{version}/{repo}.json",
                        Path(data) / f"alpine_{version}_{repo}.json")
        if not raw:
            continue
        for item in json.loads(raw).get("packages", []):
            p = item["pkg"]
            out.setdefault(p["name"], {}).update(p.get("secfixes") or {})
    _alpine_cache[version] = out
    return out


def ubuntu_cve(data, cve):
    path = Path(data) / "ubuntu" / f"{cve}.json"
    raw = try_fetch(f"https://ubuntu.com/security/cves/{cve}.json", path)
    return json.loads(raw) if raw else None


# ---------------------------------------------------------- version compare
def _order(ch):
    if ch is None or ch.isdigit():
        return 0
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _dpkg_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else None)
            bc = _order(b[j] if j < len(b) else None)
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        si = i
        while i < len(a) and a[i].isdigit():
            i += 1
        sj = j
        while j < len(b) and b[j].isdigit():
            j += 1
        na, nb = int(a[si:i] or 0), int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split_deb(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    rev = ""
    if "-" in v:
        v, rev = v.rsplit("-", 1)
    return epoch, v, rev


def dpkg_cmp(a, b):
    ea, ua, ra = _split_deb(a)
    eb, ub, rb = _split_deb(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


PRE = {"alpha", "beta", "pre", "rc"}


def apk_cmp(a, b):
    """Approximate apk version comparison (good for typical 1.2.3-r4 versions)."""
    ta = re.findall(r"\d+|[a-z]+", a.lower())
    tb = re.findall(r"\d+|[a-z]+", b.lower())
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            s = y if x.isdigit() else x
            if s in PRE:
                return 1 if x.isdigit() else -1
            return -1 if x.isdigit() else 1
        return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    longer_is_a = len(ta) > len(tb)
    nxt = (ta if longer_is_a else tb)[min(len(ta), len(tb))]
    longer_greater = nxt not in PRE
    if longer_is_a:
        return 1 if longer_greater else -1
    return -1 if longer_greater else 1


# ------------------------------------------------------------- load scans
def load_trivy(path):
    d = json.load(open(path))
    osinfo = (d.get("Metadata") or {}).get("OS") or {}
    rows = []
    for res in d.get("Results") or []:
        kind = "os" if res.get("Class") == "os-pkgs" else "lang"
        # source package names come from the package list (scan.sh uses --list-all-pkgs)
        srcmap = {p.get("Name"): p.get("SrcName", "") for p in res.get("Packages") or []}
        for v in res.get("Vulnerabilities") or []:
            rows.append(dict(tool="trivy", cve=v["VulnerabilityID"], pkg=v.get("PkgName", ""),
                             version=v.get("InstalledVersion", ""), fixed=v.get("FixedVersion", ""),
                             severity=(v.get("Severity") or "UNKNOWN").upper(), kind=kind,
                             src=srcmap.get(v.get("PkgName"), "")))
    return rows, osinfo.get("Family"), osinfo.get("Name")


def load_grype(path):
    d = json.load(open(path))
    distro = d.get("distro") or {}
    rows = []
    for m in d.get("matches") or []:
        v, a = m["vulnerability"], m["artifact"]
        cve = v["id"]
        if not cve.startswith("CVE-"):
            rel = [r["id"] for r in m.get("relatedVulnerabilities") or [] if r["id"].startswith("CVE-")]
            if rel:
                cve = rel[0]
        kind = "os" if a.get("type") in ("deb", "apk", "rpm") else "lang"
        ups = a.get("upstreams") or []
        fixed = ",".join((v.get("fix") or {}).get("versions") or [])
        rows.append(dict(tool="grype", cve=cve, pkg=a.get("name", ""), version=a.get("version", ""),
                         fixed=fixed, severity=(v.get("severity") or "Unknown").upper(), kind=kind,
                         src=(ups[0]["name"] if ups and "name" in ups[0] else "")))
    return rows, distro.get("name"), distro.get("version")


def load_all(results):
    frames, osmap = [], {}
    for tool, loader in (("trivy", load_trivy), ("grype", load_grype)):
        for f in sorted(Path(results, tool).glob("*.json")):
            rows, fam, ver = loader(f)
            for r in rows:
                r["image"] = f.stem
            frames.extend(rows)
            if fam and f.stem not in osmap:
                osmap[f.stem] = (str(fam).lower(), str(ver))
    return pd.DataFrame(frames), osmap


# ------------------------------------------------------------ ground truth
def verdict(row, osinfo, ctx):
    """Return (TP | FP | UNVERIFIED, reason) for one OS package finding."""
    if row.kind != "os":
        return "UNVERIFIED", "language package, no distro tracker"
    fam, ver = osinfo
    if fam == "debian":
        major = ver.split(".")[0]
        code = DEBIAN_CODENAMES.get(major)
        if not code:
            return "UNVERIFIED", f"unknown debian release {ver}"
        for src in [s for s in (row.src, row.pkg) if s]:
            entry = (ctx["debian"].get(src) or {}).get(row.cve)
            if not entry:
                continue
            rel = (entry.get("releases") or {}).get(code)
            if not rel:
                return "UNVERIFIED", "no entry for this release in Debian tracker"
            status, fixed = rel.get("status"), rel.get("fixed_version")
            if status == "resolved":
                if fixed in (None, "", "0"):
                    return "FP", "Debian: not affected"
                if dpkg_cmp(row.version, fixed) >= 0:
                    return "FP", f"Debian: fixed in {fixed}"
                return "TP", f"Debian: fixed only in {fixed}"
            if status == "open":
                return "TP", "Debian: open"
            return "UNVERIFIED", f"Debian status {status}"
        return "UNVERIFIED", "CVE not in Debian tracker for this package"
    if fam == "alpine":
        rel = ".".join(ver.split(".")[:2])
        fixes = alpine_secfixes(ctx["data"], rel).get(row.src or row.pkg) or alpine_secfixes(
            ctx["data"], rel).get(row.pkg)
        if not fixes:
            return "UNVERIFIED", "package not in Alpine secdb"
        for fixed, cves in fixes.items():
            if row.cve in cves:
                if apk_cmp(row.version, fixed) >= 0:
                    return "FP", f"Alpine: fixed in {fixed}"
                return "TP", f"Alpine: fixed only in {fixed}"
        return "UNVERIFIED", "CVE not listed in Alpine secdb"
    if fam == "ubuntu":
        code = UBUNTU_CODENAMES.get(ver)
        data = ubuntu_cve(ctx["data"], row.cve)
        if not code or not data:
            return "UNVERIFIED", "Ubuntu data unavailable"
        names = {row.pkg, row.src}
        for p in data.get("packages") or []:
            if p.get("name") not in names:
                continue
            for st in p.get("statuses") or []:
                if st.get("release_codename") != code:
                    continue
                s, desc = st.get("status"), st.get("description") or ""
                if s in ("not-affected", "DNE"):
                    return "FP", f"Ubuntu: {s}"
                if s == "released":
                    if desc and dpkg_cmp(row.version, desc) >= 0:
                        return "FP", f"Ubuntu: fixed in {desc}"
                    return "TP", f"Ubuntu: fixed only in {desc}"
                if s in ("needed", "deferred", "ignored", "pending"):
                    return "TP", f"Ubuntu: {s}"
        return "UNVERIFIED", "not found in Ubuntu tracker"
    return "UNVERIFIED", f"no tracker for {fam}"


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    print("Loading scan results ...")
    df, osmap = load_all(a.results)
    if df.empty:
        sys.exit("No findings loaded. Run scan.sh first.")
    df["pkg"] = df["pkg"].str.lower()
    # share binary to source package names between tools, so both get the same verdict
    srcs = df[df.src != ""].drop_duplicates(["image", "pkg"]).set_index(["image", "pkg"])["src"].to_dict()
    df["src"] = [s or srcs.get((i, p), "") for s, i, p in zip(df.src, df.image, df.pkg)]
    df = df.drop_duplicates(subset=["image", "tool", "cve", "pkg", "version"])

    print("Loading trackers, EPSS and KEV (first run downloads data) ...")
    ctx = {"data": a.data, "debian": load_debian(a.data) if any(f == "debian" for f, _ in osmap.values()) else {}}
    kev = load_kev(a.data)
    epss = load_epss(a.data)

    print("Building the reference set ...")
    cache = {}
    verd, why = [], []
    for row in df.itertuples():
        key = (row.image, row.cve, row.pkg, row.version)
        if key not in cache:
            cache[key] = verdict(row, osmap.get(row.image, ("", "")), ctx)
        verd.append(cache[key][0])
        why.append(cache[key][1])
    df["verdict"], df["reason"] = verd, why
    df["kev"] = df["cve"].isin(kev)
    df["epss"] = df["cve"].map(epss)
    df.to_csv(out / "findings_all.csv", index=False)

    # ---- counts per tool, image, severity
    sev = (df.groupby(["image", "tool", "severity"]).size().unstack(fill_value=0)
           .reindex(columns=[s for s in SEV_ORDER if s in df["severity"].unique()], fill_value=0))
    sev.to_csv(out / "severity_counts.csv")

    # ---- reference set (OS packages only)
    osdf = df[df["kind"] == "os"].copy()
    ref = osdf[osdf["verdict"] == "TP"][["image", "cve", "pkg"]].drop_duplicates()
    ref_keys = set(map(tuple, ref.values))
    rows = []
    for tool in ("trivy", "grype"):
        t = osdf[osdf["tool"] == tool]
        tp = t[t["verdict"] == "TP"]
        fp = t[t["verdict"] == "FP"]
        un = t[t["verdict"] == "UNVERIFIED"]
        found = set(map(tuple, tp[["image", "cve", "pkg"]].drop_duplicates().values))
        n_tp, n_fp = len(found), len(fp[["image", "cve", "pkg"]].drop_duplicates())
        rows.append(dict(tool=tool, os_findings=len(t), true_positive=n_tp, false_positive=n_fp,
                         unverified=len(un), false_negative=len(ref_keys - found),
                         precision=round(n_tp / (n_tp + n_fp), 3) if n_tp + n_fp else None,
                         recall=round(n_tp / len(ref_keys), 3) if ref_keys else None))
    metrics = pd.DataFrame(rows)
    metrics.to_csv(out / "precision_recall.csv", index=False)

    # ---- disagreements
    key = ["image", "cve", "pkg"]
    tri = df[df.tool == "trivy"].drop_duplicates(key)
    gry = df[df.tool == "grype"].drop_duplicates(key)
    m = tri.merge(gry, on=key, how="outer", suffixes=("_t", "_g"), indicator=True)
    both = int((m["_merge"] == "both").sum())
    only_t = m[m["_merge"] == "left_only"].copy()
    only_g = m[m["_merge"] == "right_only"].copy()

    def cause(r, sfx, other):
        v = r["verdict" + sfx]
        reason = r["reason" + sfx]
        kind = r["kind" + sfx]
        if kind == "lang":
            return "language package (no distro tracker)"
        if v == "FP":
            return "reported by this tool only, tracker says fixed or not affected (distro advisory / backport)"
        if v == "TP":
            return f"missed by {other} (false negative of {other})"
        return "could not be verified"

    dis = []
    for r in only_t.to_dict("records"):
        dis.append(dict(image=r["image"], cve=r["cve"], pkg=r["pkg"], reported_by="trivy only",
                        verdict=r["verdict_t"], reason=r["reason_t"], cause=cause(r, "_t", "grype"),
                        severity=r["severity_t"], kev=r["kev_t"], epss=r["epss_t"]))
    for r in only_g.to_dict("records"):
        dis.append(dict(image=r["image"], cve=r["cve"], pkg=r["pkg"], reported_by="grype only",
                        verdict=r["verdict_g"], reason=r["reason_g"], cause=cause(r, "_g", "trivy"),
                        severity=r["severity_g"], kev=r["kev_g"], epss=r["epss_g"]))
    dis = pd.DataFrame(dis)
    dis.to_csv(out / "disagreements.csv", index=False)
    causes = (dis.groupby(["reported_by", "cause"]).size().reset_index(name="count")
              if not dis.empty else pd.DataFrame())
    causes.to_csv(out / "disagreement_causes.csv", index=False)

    # ---- risk view (EPSS, KEV, CVSS severity)
    risk = []
    kev_ref = set(map(tuple, osdf[(osdf.verdict == "TP") & osdf.kev][key].drop_duplicates().values))
    for tool in ("trivy", "grype"):
        t = df[df.tool == tool].drop_duplicates(key)
        ch = t[t.severity.isin(["CRITICAL", "HIGH"])]
        t_os = osdf[(osdf.tool == tool) & (osdf.verdict == "TP") & osdf.kev]
        found_kev = set(map(tuple, t_os[key].drop_duplicates().values))
        risk.append(dict(
            tool=tool, findings=len(t), in_kev=int(t.kev.sum()),
            epss_ge_0_1=int((t.epss >= 0.1).sum()), epss_ge_0_01=int((t.epss >= 0.01).sum()),
            critical_high=len(ch),
            critical_high_epss_below_0_01=int((ch.epss.fillna(0) < 0.01).sum()),
            critical_high_in_kev=int(ch.kev.sum()),
            verified_kev_found=len(found_kev), verified_kev_total=len(kev_ref)))
    risk = pd.DataFrame(risk)
    risk.to_csv(out / "risk_view.csv", index=False)

    # ---- timings
    tpath = Path(a.results) / "timings.csv"
    timings = pd.read_csv(tpath) if tpath.exists() else pd.DataFrame()
    if not timings.empty:
        timings.pivot(index="image", columns="tool", values="milliseconds").to_csv(out / "timings_pivot.csv")

    # ---- plain markdown summary
    def md(d):
        return d.to_markdown(index=False) if not d.empty else "(none)"
    try:
        import tabulate  # noqa: F401
    except ImportError:
        md = lambda d: d.to_string(index=False) if not d.empty else "(none)"  # noqa: E731
    lines = ["# Trivy vs Grype results", "",
             f"Images scanned: {', '.join(sorted(df.image.unique()))}",
             f"Findings in common (same CVE and package): {both}",
             f"Reported by Trivy only: {len(only_t)}", f"Reported by Grype only: {len(only_g)}", "",
             "## Precision and recall (OS packages, against the distro tracker reference set)", md(metrics), "",
             f"Reference set size: {len(ref_keys)} verified real findings", "",
             "## Why the tools disagree", md(causes), "",
             "## Risk view", md(risk), "",
             "## Findings per severity", md(sev.reset_index()), ""]
    if not timings.empty:
        lines += ["## Scan time (ms)", md(timings.pivot(index="image", columns="tool",
                                                         values="milliseconds").reset_index()), ""]
    (out / "summary.md").write_text("\n".join(lines))

    # ---- charts
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tot = df.groupby(["image", "tool"]).size().unstack(fill_value=0)
    ax = tot.plot(kind="bar", color=["#555555", "#aaaaaa"], figsize=(9, 5))
    ax.set_ylabel("findings")
    ax.set_title("Findings per image")
    plt.tight_layout()
    plt.savefig(out / "findings_per_image.png", dpi=150)
    plt.close()

    ax = metrics.set_index("tool")[["precision", "recall"]].plot(
        kind="bar", color=["#555555", "#aaaaaa"], figsize=(6, 4), ylim=(0, 1.05))
    ax.set_title("Precision and recall (OS packages)")
    plt.tight_layout()
    plt.savefig(out / "precision_recall.png", dpi=150)
    plt.close()

    ax = risk.set_index("tool")[["in_kev", "epss_ge_0_1", "critical_high_epss_below_0_01"]].plot(
        kind="bar", color=["#222222", "#777777", "#bbbbbb"], figsize=(7, 4))
    ax.set_title("Risk view: KEV, high EPSS, and Critical/High with low EPSS")
    plt.tight_layout()
    plt.savefig(out / "risk_view.png", dpi=150)
    plt.close()

    print(f"Done. See {out}/summary.md and the CSV files.")


if __name__ == "__main__":
    main()
