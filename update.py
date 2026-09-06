"""Build routing profiles from YOTA's current service list. Python 3.12+, stdlib.

Only the reviewed catalogue supplies domains. Page trackers, advertisements,
navigation links and guessed brand domains never become DIRECT rules.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import time
import unicodedata
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
YOTA = "https://www.yota.ru/whitelist"
GEO_REPO = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"


class PageError(ValueError):
    pass


class TextReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.anchors = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.anchors.append(dict(attrs).get("href", ""))


def plain(value):
    reader = TextReader()
    reader.feed(value)
    return " ".join(" ".join(reader.parts).split())


def normalize(value):
    value = unicodedata.normalize("NFKC", value).casefold().replace("ё", "е")
    return " ".join(re.sub(r"[^\w]+", " ", value, flags=re.UNICODE).split())


def contains(text, phrase):
    return " " + normalize(phrase) + " " in " " + normalize(text) + " "


class StateReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.inside = False
        self.parts = []
        self.count = 0

    def handle_starttag(self, tag, attrs):
        if tag == "script" and dict(attrs).get("id") == "ng-state":
            self.inside = True
            self.count += 1

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside = False


def parse_page(document):
    parser = StateReader()
    parser.feed(document)
    if parser.count != 1:
        raise PageError("YOTA page has no unique ng-state; keeping last published files")
    state = json.loads("".join(parser.parts))
    cards, overlays = [], {}
    for key, value in state.items():
        if not key.startswith("portlet-content-/whitelist-"):
            continue
        body = value.get("body", {})
        kind = body.get("portletName")
        if kind not in ("cards_with_tabs", "esim-overlay"):
            continue
        settings = json.loads(body["settings"])
        if kind == "cards_with_tabs":
            if normalize(plain(settings.get("title", ""))) != normalize("Какие сервисы продолжат работать"):
                continue
            for tab in settings.get("tabs", []):
                cards.extend(tab.get("cards", []))
        else:
            for tab in settings.get("tabs", []):
                key = tab.get("hash", "")
                if key:
                    if key in overlays:
                        raise PageError("Duplicate YOTA overlay")
                    overlays[key] = plain(tab.get("text", ""))
    if not 10 <= len(cards) <= 100:
        raise PageError("YOTA service table looks incomplete; keeping last published files")
    sections = []
    for card in cards:
        title = plain(card.get("cardTitle", ""))
        text = plain(card.get("cardText", ""))
        links = TextReader()
        links.feed(card.get("cardText", ""))
        for anchor in links.anchors:
            if anchor.startswith("#"):
                key = anchor[1:]
                if key not in overlays or not overlays[key]:
                    raise PageError(f"Missing linked YOTA overlay: {key}")
                text += ", " + overlays[key]
        if not title or not text:
            raise PageError("Empty YOTA card")
        sections.append({"title": title, "text": text})
    if len({normalize(s["title"]) for s in sections}) != len(sections):
        raise PageError("Duplicate YOTA section")
    return sections


def select_services(catalog, sections):
    selected, evidence = [], {}
    for service in catalog["services"]:
        scope = {normalize(s) for s in service["sections"]}
        matched = []
        for section in sections:
            if normalize(section["title"]) not in scope:
                continue
            group = service.get("all_services_title")
            if group and normalize(section["title"]) == normalize(group):
                matched.append({"section": section["title"], "match": group})
            else:
                for alias in service["aliases"]:
                    content = section["title"] if normalize(section["title"]) == "yota" else section["text"]
                    if contains(content, alias):
                        matched.append({"section": section["title"], "match": alias})
                        break
        if matched:
            selected.append(service)
            evidence[service["id"]] = matched
    return selected, evidence


def unmapped_mentions(catalog, sections):
    result = []
    for section in sections:
        scoped = [s for s in catalog["services"] if normalize(section["title"]) in {normalize(t) for t in s["sections"]}]
        if normalize(section["title"]) == "yota" or any(normalize(s.get("all_services_title", "")) == normalize(section["title"]) for s in scoped):
            continue
        for fragment in section["text"].split(","):
            text = fragment.strip()
            if text and not any(contains(text, alias) for s in scoped for alias in s["aliases"]):
                result.append({"section": section["title"], "text": text})
    return result


def domain(value):
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if "." not in value or len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Invalid domain in reviewed catalogue")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise ValueError("Invalid DNS label")
    return value


def suffix_match(host, domains):
    parts = host.lower().rstrip(".").split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts)))


def direct_domains(selected):
    names = {domain(name) for entry in selected for name in entry["domains"]}
    return sorted(name for name in names if not suffix_match(".".join(name.split(".")[1:]), names))


def varint(data, pos):
    number = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        number |= (byte & 127) << shift
        if byte < 128:
            return number, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("Invalid protobuf varint")


def fields(data):
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 2:
            size, pos = varint(data, pos)
            value = data[pos:pos + size]
            if len(value) != size:
                raise ValueError("Truncated protobuf")
            pos += size
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value, pos = data[pos:pos + size], pos + size
        else:
            raise ValueError("Unsupported protobuf wire type")
        yield number, value


def read_tags(data):
    tags = {}
    for number, raw in fields(data):
        if number != 1:
            continue
        items = list(fields(raw))
        name = next(v.decode().lower() for n, v in items if n == 1)
        if name in ("apple", "category-ads-all"):
            entries = []
            for n, raw_domain in items:
                if n == 2:
                    item = dict(fields(raw_domain))
                    entries.append((item.get(1, 0), item[2].decode()))
            tags[name] = entries
    if not tags.get("apple") or len(tags.get("category-ads-all", [])) < 1000:
        raise ValueError("Required Apple or advertising category missing")
    return tags


class Matcher:
    def __init__(self, entries):
        self.suffix = {v for k, v in entries if k == 2}
        self.full = {v for k, v in entries if k == 3}
        self.plain = [v for k, v in entries if k == 0]
        self.regex = [re.compile(v) for k, v in entries if k == 1]

    def matches(self, host):
        return (host in self.full or suffix_match(host, self.suffix)
                or any(v in host for v in self.plain)
                or any(r.search(host) for r in self.regex))


def make_profiles(base, selected, tags, geourls, updated):
    result = copy.deepcopy(base)
    direct = set(direct_domains(selected))
    ads, apple = Matcher(tags["category-ads-all"]), Matcher(tags["apple"])
    # A new catalogue entry cannot silently put Apple or a top-level ad root in DIRECT.
    conflicts = [name for name in sorted(direct) if apple.matches(name) or ads.matches(name)]
    if conflicts:
        raise ValueError("Catalogue conflicts with Apple/advertising rules: " + ", ".join(conflicts))
    for kind, name in tags["apple"]:
        if kind in (2, 3) and suffix_match(name, direct):
            raise ValueError("DIRECT parent would include an Apple domain: " + name)
    result.update({"LastUpdated": str(updated), "GlobalProxy": "true", "DomainStrategy": "AsIs",
                   "DirectSites": ["domain:" + name for name in sorted(direct)], "DirectIp": ["geoip:private"],
                   "Geoipurl": geourls["geoip.dat"], "Geositeurl": geourls["geosite.dat"]})
    result["DnsHosts"] = {"dns.adguard-dns.com": "94.140.14.14"}
    for rule in result["BlockSites"]:
        if rule.startswith("domain:"):
            result["DnsHosts"][rule] = "0.0.0.0"
    for kind, name in tags["category-ads-all"]:
        if kind in (2, 3) and suffix_match(name, direct):
            result["DnsHosts"][("domain:" if kind == 2 else "full:") + name] = "0.0.0.0"
    if "geosite:apple" not in result["ProxySites"]:
        raise ValueError("Apple VPN rule is mandatory")
    result.pop("UseChunkFiles", None)
    result.pop("RouteOrder", None)
    result["useChunkFiles"] = True
    happ = copy.deepcopy(result)
    happ.pop("useChunkFiles", None)
    happ.update({"UseChunkFiles": "true", "RouteOrder": "block-proxy-direct"})
    return {"Incy": result, "Happ": happ}


def fetch(url, limit=32_000_000):
    headers = {"User-Agent": "YOTA-iPhone-routing-updater/1.0", "Accept-Encoding": "identity"}
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    last = None
    for attempt in range(3):
        try:
            with urlopen(Request(url, headers=headers), timeout=45) as response:
                value = response.read(limit + 1)
                if len(value) > limit:
                    raise ValueError("Remote file exceeds expected maximum size")
                return value
        except Exception as error:
            last = error
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError("Failed downloading public routing source: " + url) from last


def geodata():
    release = json.loads(fetch(GEO_REPO, 1_000_000))
    tag = release["tag_name"]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise ValueError("Unexpected geodata release tag")
    prefix = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/" + tag + "/"
    urls = {name: prefix + name for name in ("geoip.dat", "geosite.dat")}
    expected = fetch(urls["geosite.dat"] + ".sha256sum", 1024).decode().split()[0]
    # The official project currently publishes .sha256sum checksum files.
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("Invalid official geosite checksum")
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    path = cache / "geosite.dat"
    data = path.read_bytes() if path.exists() else b""
    if hashlib.sha256(data).hexdigest() != expected.lower():
        data = fetch(urls["geosite.dat"])
        if hashlib.sha256(data).hexdigest() != expected.lower():
            raise ValueError("Geosite SHA256 mismatch")
        path.write_bytes(data)
    return read_tags(data), urls, {"release": tag, "geosite_sha256": expected.lower()}


def routing_link(app, profile):
    raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()
    link = app.lower() + "://routing/onadd/" + base64.b64encode(raw).decode()
    if json.loads(base64.b64decode(link.split("onadd/", 1)[1])) != profile:
        raise ValueError("Routing link roundtrip failed")
    return link


def write_outputs(out, profiles, report, source_url):
    texts = {}
    links = {}
    for app, profile in profiles.items():
        texts[f"{app}-YOTA-Whitelist.json"] = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
        links[app] = routing_link(app, profile)
        texts[f"{app}-import.txt"] = links[app] + "\n"
    texts["Happ-routing-body.txt"] = "#profile-update-interval: 12\n" + links["Happ"] + "\n"
    texts["status.json"] = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    texts["review-needed.json"] = json.dumps(report["unmapped_mentions"], ensure_ascii=False, indent=2) + "\n"
    texts["direct-domains.txt"] = "\n".join(rule.split(":", 1)[1] for rule in profiles["Incy"]["DirectSites"]) + "\n"
    if source_url:
        auto = "incy://autorouting/onadd/" + source_url
        texts["Incy-auto-import.txt"] = auto + "\n"
        auto_ui = f'<p><a class="button" href="{html.escape(auto, quote=True)}">Incy: добавить с автообновлением</a></p><p>В Incy выбери частоту обновления 12 часов и проверь значок облака у профиля.</p>'
    else:
        auto_ui = '<p class="notice">Автообновление ещё не подключено: нужен опубликованный адрес профиля. Ниже доступен обычный импорт текущих правил.</p>'
    texts["index.html"] = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>YOTA — маршрутизация iPhone</title><style>body{font:17px/1.55 system-ui;max-width:760px;margin:40px auto;padding:0 20px;background:#0d1420;color:#edf4ff}a{color:#77d7ff}.button{display:inline-block;background:#83ddff;color:#071521;padding:12px 18px;border-radius:12px;text-decoration:none;margin:5px 0}.notice{padding:14px;background:#28364a;border-radius:12px}textarea{width:100%;box-sizing:border-box;min-height:100px;background:#182334;color:white;border:1px solid #43566d;border-radius:8px;padding:10px}details{margin:18px 0}small{color:#b2c3d5}</style><h1>YOTA · iPhone</h1><p>Официальный белый список → DIRECT.<br>Apple и остальные сайты → VPN.<br>Рекламные домены → блокировка.</p>''' + auto_ui
    for app in ("Incy", "Happ"):
        escaped = html.escape(links[app], quote=True)
        texts["index.html"] += f'<details><summary>{app}: импорт текущего профиля</summary><p><a class="button" href="{escaped}">Открыть в {app}</a></p><textarea readonly onclick="this.select()">{escaped}</textarea><small>Это разовый импорт. Сам по себе он не включает обновление белого списка.</small></details>'
    texts["index.html"] += '<p>Для Happ обновляемые правила передаются внутри твоей подписки VPN. Файл Happ-routing-body.txt содержит добавку для провайдера, без VPN-серверов.</p><p>После изменения правил переподключи VPN. Доступность туннеля при ограничениях YOTA зависит от твоего VPN-сервера.</p>'
    texts["index.html"] += f'<p><small>Проверка списка: {html.escape(report["checked_at"])}. Групп сервисов: {report["active_services_count"]}; правил DIRECT: {report["direct_domains_count"]}. Новым сервисам без известного домена нужна проверка.</small></p><p><a href="status.json">Состав и источник</a> · <a href="review-needed.json">Неизвестные адреса</a></p></html>\n'
    # All parsing and policy validation finished before touching the published files.
    out.mkdir(parents=True, exist_ok=True)
    for name, value in texts.items():
        temporary = out / (name + ".tmp")
        temporary.write_text(value, encoding="utf-8", newline="\n")
        temporary.replace(out / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", help="Public GitHub repository, owner/name")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if args.repository and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("--repository must be owner/name")
    catalog = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    base = json.loads((ROOT / "profile-base.json").read_text(encoding="utf-8"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        page_future = pool.submit(fetch, YOTA, 2_000_000)
        geo_future = pool.submit(geodata)
        page = page_future.result()
        sections = parse_page(page.decode("utf-8"))
        tags, urls, geo_report = geo_future.result()
    selected, evidence = select_services(catalog, sections)
    if len(selected) < 50:
        raise PageError("Too few recognized services; keeping last published files")
    previous_path = args.out / "status.json"
    previous = json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.exists() else {}
    old_ids = set(previous.get("active_service_ids", []))
    new_ids = {s["id"] for s in selected}
    if old_ids and len(new_ids & old_ids) < len(old_ids) * 0.7:
        raise PageError("Over 30% of the previous list vanished; source needs review before publishing")
    checked = int(time.time())
    updated = max(checked, int(previous.get("profile_version", 0)) + 1)
    profiles = make_profiles(base, selected, tags, urls, updated)
    unknown = unmapped_mentions(catalog, sections)
    source_url = (f"https://raw.githubusercontent.com/{args.repository}/{quote(args.branch, safe='')}/dist/Incy-YOTA-Whitelist.json" if args.repository else None)
    report = {
        "checked_at": datetime.fromtimestamp(checked, timezone.utc).isoformat(),
        "profile_version": updated, "source": YOTA,
        "scope": "Federal services; region unspecified",
        "source_sha256": hashlib.sha256(page).hexdigest(),
        "catalog_sha256": hashlib.sha256((ROOT / "catalog.json").read_bytes()).hexdigest(),
        "active_services_count": len(selected), "direct_domains_count": len(profiles["Incy"]["DirectSites"]),
        "active_service_ids": sorted(new_ids), "added_service_ids": sorted(new_ids - old_ids),
        "removed_service_ids": sorted(old_ids - new_ids),
        "services": [{"id": s["id"], "name": s["name"], "domains": s["domains"], "evidence": evidence[s["id"]]} for s in selected],
        "sections": sections, "unmapped_mentions": unknown, "geodata": geo_report,
        "incy_source_url": source_url,
        "deployment": "URLs generated; hosting and iPhone subscription must be verified separately" if source_url else "Local build only; automatic updates not connected",
        "limitations": ["Official list names services, not their complete domain/IP ACL.", "New unrecognized services remain via VPN until domain review.", "Happ routing must be included in its VPN subscription.", "iOS can delay background refresh; reconnect after routing changes.", "No iPhone/YOTA-whitelist runtime test performed."],
    }
    write_outputs(args.out, profiles, report, source_url)
    print(json.dumps({"services": len(selected), "direct_domains": report["direct_domains_count"], "unmapped_mentions": len(unknown), "geodata_release": geo_report["release"], "out": str(args.out)}, ensure_ascii=False))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
