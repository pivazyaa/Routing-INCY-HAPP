"""Tests for changes that can accidentally reroute a user's connections."""
import copy
import base64
import json
from pathlib import Path
import unittest

import update
import happ_subscription

ROOT = Path(__file__).resolve().parent
CATALOG = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
BASE = json.loads((ROOT / "profile-base.json").read_text(encoding="utf-8"))


def page(cards, overlays=()):
    state = {
        "portlet-content-/whitelist-main": {"body": {
            "portletName": "cards_with_tabs",
            "settings": json.dumps({"title": "Какие сервисы продолжат работать", "tabs": [{"cards": cards}]}),
        }}
    }
    for index, (key, text) in enumerate(overlays):
        state[f"portlet-content-/whitelist-overlay-{index}"] = {"body": {
            "portletName": "esim-overlay",
            "settings": json.dumps({"tabs": [{"hash": key, "text": text}]}),
        }}
    return '<script id="ng-state" type="application/json">' + json.dumps(state) + '</script>'


def padded(card):
    return [card] + [{"cardTitle": f"Other {i}", "cardText": "Unmapped service"} for i in range(9)]


class MembershipTests(unittest.TestCase):
    def domains(self, sections):
        return set(update.direct_domains(update.select_services(CATALOG, sections)[0]))

    def test_add_remove_and_readd_known_bank(self):
        before = [{"title": "Банки", "text": "ПСБ, ВТБ, Альфа-Банк"}]
        removed = [{"title": "Банки", "text": "ПСБ, Альфа-Банк"}]
        self.assertIn("vtb.ru", self.domains(before))
        self.assertNotIn("vtb.ru", self.domains(removed))
        self.assertIn("vtb.ru", self.domains(before))

    def test_unknown_service_and_nonwhitelisted_banks_stay_vpn(self):
        domains = self.domains([{"title": "Банки", "text": "ВТБ, Новый Банк"}])
        for host in ("sberbank.ru", "tbank.ru", "new-bank.ru", "apple.com", "example.ru"):
            self.assertFalse(update.suffix_match(host, domains), host)

    def test_payment_mir_does_not_enable_tv_mir(self):
        domains = self.domains([{"title": "Банки", "text": "платежная система Мир, Mir Pay"}])
        self.assertIn("nspk.ru", domains)
        self.assertNotIn("mir24.tv", domains)

    def test_cyrillic_dash_case_and_spaces(self):
        domains = self.domains([{"title": "Банки", "text": "АЛЬФА‑БАНК, ВТБ"}])
        self.assertIn("alfabank.ru", domains)
        self.assertFalse(update.contains("неВТБ", "ВТБ"))

    def test_removing_all_vk_group_removes_implicit_services(self):
        group = [{"title": "Все сервисы VK", "text": "Например, ВКонтакте, Mail.ru"}]
        narrowed = [{"title": "Сервисы VK", "text": "Mail.ru"}]
        self.assertIn("vk.com", self.domains(group))
        self.assertNotIn("vk.com", self.domains(narrowed))
        self.assertIn("mail.ru", self.domains(narrowed))

    def test_unknown_service_is_reported(self):
        result = update.unmapped_mentions(CATALOG, [{"title": "Банки", "text": "ВТБ, Совсем новый банк"}])
        self.assertEqual([r["text"] for r in result], ["Совсем новый банк"])

    def test_names_and_domains_have_unique_identifiers(self):
        ids = [s["id"] for s in CATALOG["services"]]
        self.assertEqual(len(ids), len(set(ids)))
        for service in CATALOG["services"]:
            for host in service["domains"]:
                update.domain(host)


class SourceParsingTests(unittest.TestCase):
    def test_linked_overlay_is_included(self):
        cards = padded({"cardTitle": "Банки", "cardText": 'ВТБ и <a href="#banks">другие</a>'})
        sections = update.parse_page(page(cards, [("banks", "Альфа-Банк")]))
        domains = update.direct_domains(update.select_services(CATALOG, sections)[0])
        self.assertIn("alfabank.ru", domains)

    def test_unlinked_stale_overlay_does_not_preserve_removed_bank(self):
        cards = padded({"cardTitle": "Банки", "cardText": "ВТБ"})
        sections = update.parse_page(page(cards, [("banks", "Альфа-Банк")]))
        domains = update.direct_domains(update.select_services(CATALOG, sections)[0])
        self.assertNotIn("alfabank.ru", domains)

    def test_missing_overlay_and_captcha_abort(self):
        cards = padded({"cardTitle": "Банки", "cardText": 'ВТБ и <a href="#missing">другие</a>'})
        for document in ("<html>captcha</html>", page(cards), page(cards[:1])):
            with self.assertRaises(update.PageError):
                update.parse_page(document)

    def test_trackers_outside_service_cards_are_ignored(self):
        cards = padded({"cardTitle": "Банки", "cardText": "ВТБ"})
        content = '<img src="https://tracking.example.ru/pixel"><p>Сбербанк</p>' + page(cards)
        sections = update.parse_page(content)
        self.assertNotIn("tracking", json.dumps(sections))
        self.assertNotIn("Сбербанк", str(sections))


class SubscriptionTests(unittest.TestCase):
    # Deliberately fake, non-routable test endpoint; no real credentials.
    SERVER = "vless://00000000-0000-0000-0000-000000000000@test.invalid:443#Test"

    def test_replace_old_routing_preserving_servers(self):
        body = ("#profile-title: My VPN\n#profile-update-interval: 1\n"
                "#routing-enable: 0\nhapp://routing/onadd/old\n" + self.SERVER)
        result = happ_subscription.combine(body.encode(), BASE)
        self.assertIn(self.SERVER, result)
        self.assertIn("#profile-title: My VPN", result)
        self.assertNotIn("onadd/old", result)
        self.assertNotIn("#routing-enable:", result)
        self.assertEqual(result.count("happ://routing/onadd/"), 1)
        self.assertTrue(result.startswith("#profile-update-interval: 12\n"))

    def test_base64_subscription(self):
        result = happ_subscription.combine(base64.b64encode(self.SERVER.encode()), BASE)
        self.assertIn(self.SERVER, result)

    def test_json_and_serverless_subscriptions_are_rejected(self):
        for content in (b'{"outbounds": []}', b'happ://routing/onadd/rules-only'):
            with self.assertRaises(ValueError):
                happ_subscription.combine(content, BASE)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tags = {"apple": [(2, "apple.com"), (2, "icloud.com"), (2, "mzstatic.com")],
                     "category-ads-all": [(2, "doubleclick.net"), (2, "mc.yandex.ru")]}
        self.urls = {"geoip.dat": "https://example.org/geoip.dat", "geosite.dat": "https://example.org/geosite.dat"}
        self.selected = update.select_services(CATALOG, [
            {"title": "Банки", "text": "ВТБ"},
            {"title": "Все сервисы Яндекса", "text": "Яндекс"},
        ])[0]

    def profiles(self, selected=None):
        return update.make_profiles(BASE, self.selected if selected is None else selected,
                                    self.tags, self.urls, 100)

    def test_apple_default_vpn_private_only_and_app_field_types(self):
        configs = self.profiles()
        for app, config in configs.items():
            self.assertEqual(config["GlobalProxy"], "true")
            self.assertEqual(config["DirectIp"], ["geoip:private"])
            self.assertIn("geosite:apple", config["ProxySites"])
            self.assertNotIn("geosite:ru", config["DirectSites"])
            for host in ("apple.com", "apps.apple.com", "icloud.com", "example.ru", "rutracker.org", "tbank.ru"):
                self.assertFalse(update.suffix_match(host, {r[7:] for r in config["DirectSites"]}), (app, host))
        self.assertIs(configs["Incy"]["useChunkFiles"], True)
        self.assertEqual(configs["Happ"]["UseChunkFiles"], "true")
        self.assertEqual(configs["Happ"]["RouteOrder"], "block-proxy-direct")

    def test_explicit_ad_domain_inside_direct_is_also_blocked_in_dns(self):
        for config in self.profiles().values():
            self.assertEqual(config["DnsHosts"]["domain:mc.yandex.ru"], "0.0.0.0")
            self.assertEqual(config["DnsHosts"]["domain:appmetrica.yandex.ru"], "0.0.0.0")

    def test_apple_or_ad_catalogue_entry_is_rejected(self):
        for name in ("apple.com", "doubleclick.net"):
            selected = copy.deepcopy(self.selected)
            selected.append({"domains": [name]})
            with self.assertRaises(ValueError):
                self.profiles(selected)

    def test_direct_suffix_boundaries(self):
        for host in ("notvtb.ru", "vtb.ru.evil.example"):
            self.assertFalse(update.suffix_match(host, {"vtb.ru"}))
        self.assertTrue(update.suffix_match("online.vtb.ru", {"vtb.ru"}))

    def test_import_roundtrip(self):
        for app, profile in self.profiles().items():
            self.assertTrue(update.routing_link(app, profile).startswith(app.lower() + "://routing/onadd/"))


if __name__ == "__main__":
    unittest.main()
