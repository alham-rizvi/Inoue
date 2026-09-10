"""Webhook payload helpers for generic, Slack, and Discord sinks."""

from __future__ import annotations

from typing import Iterable

import httpx


def _normalize_technologies(technologies: Iterable[str]) -> list[str]:
    items = [str(tech).strip() for tech in technologies if str(tech).strip()]
    return sorted(set(items))


def build_generic_payload(url: str, technologies: Iterable[str], cves: Iterable[str]) -> dict:
    return {
        "url": url,
        "technologies": _normalize_technologies(technologies),
        "cves": sorted(set(str(item).strip() for item in cves if str(item).strip())),
    }


def build_slack_payload(url: str, technologies: Iterable[str], cves: Iterable[str]) -> dict:
    techs = _normalize_technologies(technologies)
    slack_cves = sorted(set(str(item).strip() for item in cves if str(item).strip()))
    text = f"*Inoue scan*\nURL: {url}\nTechnologies: {', '.join(techs) if techs else 'none'}\nCVEs: {', '.join(slack_cves) if slack_cves else 'none'}"
    return {"text": text}


def build_discord_payload(url: str, technologies: Iterable[str], cves: Iterable[str]) -> dict:
    techs = _normalize_technologies(technologies)
    discord_cves = sorted(set(str(item).strip() for item in cves if str(item).strip()))
    return {
        "embeds": [{
            "title": "Inoue scan",
            "description": f"URL: {url}\nTechnologies: {', '.join(techs) if techs else 'none'}\nCVEs: {', '.join(discord_cves) if discord_cves else 'none'}",
            "color": 5814783,
        }]
    }


def send_webhook(url: str, payload: dict, verify: bool = True, timeout: float = 10.0) -> dict:
    """POST a payload to a user-supplied webhook URL and return the server response metadata."""
    if not url:
        raise ValueError("Webhook URL is required")

    with httpx.Client(timeout=timeout, verify=verify) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        body = response.text
        if body:
            try:
                parsed = response.json()
            except ValueError:
                parsed = body
        else:
            parsed = {}
        return {
            "ok": response.is_success,
            "status_code": response.status_code,
            "body": parsed,
        }
