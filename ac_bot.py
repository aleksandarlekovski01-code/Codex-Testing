#!/usr/bin/env python3
"""
Acceptance Criteria Bot

This bot takes a natural-language feature explanation and generates:
1) A list of measurable/testable acceptance criteria.
2) Optional Gherkin scenarios.
3) A JSON output payload with metadata.

The design is modular: each AC-generation behavior is implemented as a rule class.
New rules can be added by implementing the `BaseRule` interface and registering the
rule in `AcceptanceCriteriaGenerator`.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Protocol


@dataclass
class FeatureContext:
    """Normalized representation of a user feature request."""

    raw_text: str
    normalized_text: str = field(init=False)
    tokens: List[str] = field(init=False)
    has_email: bool = field(init=False)
    has_time_limit: bool = field(init=False)
    explicit_hours: int | None = field(init=False)
    has_security_intent: bool = field(init=False)
    has_error_handling_intent: bool = field(init=False)

    def __post_init__(self) -> None:
        self.normalized_text = " ".join(self.raw_text.strip().split()).lower()
        self.tokens = re.findall(r"[a-z0-9']+", self.normalized_text)
        self.has_email = "email" in self.tokens
        self.has_time_limit = bool(re.search(r"\b(expire|expires|valid|within|hours?|days?)\b", self.normalized_text))

        hour_match = re.search(r"(\d+)\s*hours?", self.normalized_text)
        self.explicit_hours = int(hour_match.group(1)) if hour_match else None

        self.has_security_intent = bool(
            re.search(r"\b(secure|token|one-time|once|password|auth|authentication)\b", self.normalized_text)
        )
        self.has_error_handling_intent = bool(
            re.search(r"\b(if|unless|invalid|not registered|unknown|error|fail|missing)\b", self.normalized_text)
        )


class BaseRule(Protocol):
    """Protocol for rules that add AC statements from feature context."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        ...


class CoreCapabilityRule:
    """Creates at least one AC that captures the core user outcome."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        return [
            f"Given a user requests this feature, when the request is valid, then the system completes: '{ctx.raw_text.strip()}'."
        ]


class ChannelRule:
    """Adds channel-specific AC (for example, email delivery behavior)."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        criteria: List[str] = []
        if ctx.has_email:
            criteria.append(
                "Given the user provides a registered email, when they submit the request, then the system sends the required email notification."
            )
            criteria.append(
                "Given an email is sent, when the message is generated, then it must include all data required to complete the feature flow."
            )
        return criteria


class SecurityRule:
    """Infers security expectations from wording related to auth/secrets/tokens."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        if not (ctx.has_security_intent or "reset" in ctx.tokens):
            return []
        return [
            "Given the flow uses links or tokens, when credentials are generated, then each token must be unique, unguessable, and single-use.",
            "Given sensitive operations are requested, when the request is processed, then the system must not expose whether account data exists beyond approved UX rules.",
        ]


class TimeConstraintRule:
    """Produces AC for expiry/validity windows implied by the feature description."""

    DEFAULT_HOURS = 24

    def apply(self, ctx: FeatureContext) -> List[str]:
        if not (ctx.has_time_limit or "reset" in ctx.tokens):
            return []

        expiry = ctx.explicit_hours if ctx.explicit_hours is not None else self.DEFAULT_HOURS
        return [
            f"Given a temporary credential is issued, when {expiry} hours have elapsed, then the credential is rejected as expired.",
        ]


class NegativePathRule:
    """Adds explicit error-handling AC for invalid or unknown inputs."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        if not (ctx.has_error_handling_intent or "email" in ctx.tokens or "reset" in ctx.tokens):
            return []

        return [
            "Given the provided identifier is invalid or not registered, when the request is submitted, then the system returns a generic response that does not reveal account existence.",
            "Given the request payload is missing required fields, when validation runs, then the system returns a clear validation error and does not execute the feature action.",
        ]


class ObservabilityRule:
    """Adds measurable non-functional behavior for auditing and support."""

    def apply(self, ctx: FeatureContext) -> List[str]:
        return [
            "Given a feature request is processed, when the operation completes, then the system records an audit event with timestamp and outcome.",
        ]


class AcceptanceCriteriaGenerator:
    """Coordinates rules and assembles deterministic acceptance criteria output."""

    def __init__(self, rules: List[BaseRule] | None = None) -> None:
        self.rules: List[BaseRule] = rules or [
            CoreCapabilityRule(),
            ChannelRule(),
            SecurityRule(),
            TimeConstraintRule(),
            NegativePathRule(),
            ObservabilityRule(),
        ]

    def generate(self, feature_text: str) -> List[str]:
        ctx = FeatureContext(raw_text=feature_text)
        criteria: List[str] = []

        for rule in self.rules:
            criteria.extend(rule.apply(ctx))

        # De-duplicate while preserving order.
        seen = set()
        unique_criteria = []
        for item in criteria:
            normalized = item.strip()
            if normalized not in seen:
                seen.add(normalized)
                unique_criteria.append(normalized)

        return unique_criteria


def to_gherkin(feature_text: str, criteria: List[str]) -> List[Dict[str, object]]:
    """Converts AC statements into simple Gherkin-like scenarios.

    Each AC becomes one scenario with one `Then` line for testability.
    """

    scenarios = []
    for i, ac in enumerate(criteria, start=1):
        scenarios.append(
            {
                "scenario": f"AC {i}: {feature_text[:60]}".strip(),
                "steps": [
                    "Given the system is available",
                    "When the feature flow is triggered",
                    f"Then {ac}",
                ],
            }
        )
    return scenarios


def build_output(feature_text: str, include_gherkin: bool = False) -> Dict[str, object]:
    """Builds final JSON payload with metadata + generated AC."""

    generator = AcceptanceCriteriaGenerator()
    criteria = generator.generate(feature_text)

    payload: Dict[str, object] = {
        "metadata": {
            "generator": "acceptance-criteria-bot",
            "version": "1.0.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "criteria_count": len(criteria),
            "gherkin_included": include_gherkin,
        },
        "feature": feature_text,
        "acceptance_criteria": criteria,
    }

    if include_gherkin:
        payload["gherkin_scenarios"] = to_gherkin(feature_text, criteria)

    return payload


def main() -> None:
    """CLI entry point.

    Usage examples:
      python ac_bot.py --feature "Users can reset passwords by email"
      python ac_bot.py --feature "..." --gherkin
    """

    parser = argparse.ArgumentParser(description="Generate acceptance criteria from feature text.")
    parser.add_argument("--feature", required=True, help="Natural language feature explanation.")
    parser.add_argument(
        "--gherkin",
        action="store_true",
        help="Include generated Gherkin scenarios in output JSON.",
    )

    args = parser.parse_args()
    output = build_output(feature_text=args.feature, include_gherkin=args.gherkin)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
