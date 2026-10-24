"""Own-account cloud inventory adapter; never enumerates third-party assets."""

from __future__ import annotations

from typing import Any

from core.http import normalize_url
from core.module_base import ModuleBase, ResultSet
from core.scope import Scope
from core.util import host_of
from modules.common import phase_settings

_ALLOWED_PROVIDERS = {"aws", "azure", "gcp", "cloudflare", "digitalocean", "s3", "r2"}
_ACCOUNT_KEYS = ("account_id", "project_id", "subscription_id", "tenant_id", "account")


def _account_for_provider(context: Any, provider: str) -> str | None:
    if isinstance(context, str):
        value = context.strip()
        return value[:200] if value else None
    if not isinstance(context, dict):
        return None
    provider_context = context.get(provider)
    if isinstance(provider_context, (str, int)) and str(provider_context).strip():
        return str(provider_context).strip()[:200]
    for key in _ACCOUNT_KEYS:
        value = context.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()[:200]
    return None


def _bounded_inventory(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:1000] if isinstance(item, dict)]


class Module(ModuleBase):
    name = "Cloud asset inventory"
    slug = "p14_cloud_assets"
    phase = 14
    description = "Import explicit in-scope inventory for an operator-designated account; ownership is not independently verified."
    tables = ("cloud_assets",)
    is_passive = True

    def run(self, scope: Scope, config: dict[str, Any]) -> ResultSet:
        result = self.new_result()
        settings = phase_settings(config, self.phase)
        if settings.get("enabled") is not True:
            result.note("Cloud inventory is disabled by default; set p14.enabled=true to opt in.")
            return result
        if settings.get("own_account_only", True) is not True:
            result.note("Cloud inventory refused because own_account_only must remain enabled.")
            return result

        context = settings.get("own_account_context")
        if context is None:
            context = settings.get("account_context")
        if not isinstance(context, (str, dict)) or not context:
            result.note("Cloud inventory skipped: configure an explicit own_account_context first.")
            return result

        inventory = settings.get("owned_assets")
        if inventory is None:
            inventory = settings.get("inventory")
        records = _bounded_inventory(inventory)
        if not records:
            result.note(
                "No explicit owned_assets inventory was supplied; no cloud API, bucket, or hostname probes were made."
            )
            return result

        seen: set[tuple[str, str]] = set()
        for record in records:
            provider = str(record.get("provider") or "").strip().lower()
            if provider not in _ALLOWED_PROVIDERS:
                continue
            expected_account = _account_for_provider(context, provider)
            supplied_account = ""
            for key in _ACCOUNT_KEYS:
                value = record.get(key)
                if isinstance(value, (str, int)) and str(value).strip():
                    supplied_account = str(value).strip()[:200]
                    break
            if not expected_account or supplied_account != expected_account:
                continue

            asset = str(record.get("asset") or record.get("name") or "").strip()
            if not asset or len(asset) > 300 or any(ord(char) < 32 for char in asset):
                continue
            url = normalize_url(str(record.get("url") or "")) if record.get("url") else None
            host = str(record.get("host") or host_of(url or "")).strip().lower().rstrip(".")
            if not host or not scope.allows(host):
                continue
            if url and host_of(url) != host:
                continue
            key = (provider, asset)
            if key in seen:
                continue
            seen.add(key)

            region = str(record.get("region") or "").strip()[:100] or None
            result.add(
                "cloud_assets",
                provider=provider,
                asset=asset,
                url=url,
                evidence="Operator-supplied inventory matching the configured account context; ownership was not independently verified and no probe was performed.",
                account=supplied_account,
                region=region,
                host=host,
            )

        result.note(
            f"Recorded {len(seen)} operator-supplied in-scope inventory record(s); account ownership was not independently verified and no probes were performed."
        )
        return result
