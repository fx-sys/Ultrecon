from __future__ import annotations

import pytest

from core.scope import Scope, ScopeError, normalize_hostname, parse_scope_lines


def test_normalize_hostname_and_legacy_wildcard() -> None:
    assert normalize_hostname("EXAMPLE.COM.") == ("example.com", False)
    assert normalize_hostname("*.Example.com", allow_wildcard=True) == ("example.com", True)
    assert normalize_hostname(
        "*Example*.API*.COM", allow_wildcard=True
    ) == ("*example*.api*.com", False)
    with pytest.raises(ScopeError, match="wildcard entries are not allowed"):
        normalize_hostname("*.example.com")
    with pytest.raises(ScopeError, match="wildcard entries are not allowed"):
        normalize_hostname("api*.example.com")


@pytest.mark.parametrize(
    "value",
    [
        "example",
        "https://example.com",
        "example.com:443",
        "127.0.0.1",
        "bad..example.com",
        "foo_underscore.example.com",
        "example.com/path",
        "foo**bar.example.com",
        "*.*.example.com",
        "foo.*",
        "*éxample*.com",
        "foo[ab].example.com",
        "a" * 64 + "*.example.com",
    ],
)
def test_rejects_invalid_scope_entries(value: str) -> None:
    with pytest.raises(ScopeError):
        normalize_hostname(value, allow_wildcard=True)


def test_parse_scope_deduplicates_but_preserves_bare_and_wildcard() -> None:
    scope = parse_scope_lines(
        ["# comment", "Example.com", "example.com.", "*.example.com", ""],
    )
    assert [(target.domain, target.wildcard) for target in scope.targets] == [
        ("example.com", False),
        ("example.com", True),
    ]
    assert scope.enumeration_seeds == ["example.com"]
    assert scope.allows("example.com")
    assert scope.allows("api.example.com")


def test_wildcard_is_a_boundary_not_an_expanded_seed() -> None:
    scope = parse_scope_lines("*.example.com")
    assert scope.enumeration_seeds == ["example.com"]
    assert not scope.allows("example.com")
    assert scope.allows("a.example.com")
    assert scope.allows("a.b.example.com")
    assert not scope.allows("example.org")


def test_label_local_glob_matches_whole_hostname_only() -> None:
    scope = parse_scope_lines("*example*.api*.com")

    assert scope.allows("foexamplebar.apiv1.com")
    assert scope.allows("example.api.com")
    assert scope.allows("fexample.apiv2.com.")
    assert not scope.allows("x.foexamplebar.apiv1.com")
    assert not scope.allows("foexamplebar.xapiv1.com")
    assert not scope.allows("foexamplebar.apiv1.com.evil")
    assert not scope.allows("footherbar.apiv1.com")
    assert not scope.allows("foexamplebar.apiv1.org")


def test_glob_allows_idna_in_literal_labels() -> None:
    scope = parse_scope_lines("*example*.café")

    assert scope.allows("foexamplebar.café")
    assert scope.allows("foexamplebar.xn--caf-dma")


def test_generic_globs_are_not_concrete_enumeration_seeds() -> None:
    scope = parse_scope_lines("*example*.api*.com")

    assert scope.domains == []
    assert scope.enumeration_seeds == []
    assert scope.seed_hosts() == []


def test_glob_deduplication_and_serialization_round_trip() -> None:
    scope = parse_scope_lines(
        ["*EXAMPLE*.API*.COM", "*example*.api*.com.", "*.legacy.example", "bare.example"]
    )
    restored = Scope.from_dict(scope.to_dict())

    assert [target.key for target in restored.targets] == [target.key for target in scope.targets]
    assert restored.allows("foexamplebar.apiv1.com")
    assert restored.allows("a.legacy.example")
    assert restored.allows("bare.example")
    assert not restored.allows("legacy.example")
    assert restored.enumeration_seeds == ["legacy.example", "bare.example"]


def test_legacy_serialized_scope_loads_with_original_meaning() -> None:
    scope = Scope.from_dict(
        {
            "include_subdomains": True,
            "targets": [{"raw": "*.example.com", "domain": "example.com", "wildcard": True}],
        }
    )

    assert not scope.allows("example.com")
    assert scope.allows("deep.api.example.com")


def test_resume_scope_rejects_malformed_serialized_targets() -> None:
    with pytest.raises(ScopeError, match="inconsistent"):
        Scope.from_dict(
            {
                "targets": [
                    {"raw": "outside.invalid", "domain": "example.com", "wildcard": False}
                ]
            }
        )
    with pytest.raises(ScopeError, match="include_subdomains must be a boolean"):
        Scope.from_dict(
            {
                "include_subdomains": "false",
                "targets": [{"domain": "example.com", "wildcard": False}],
            }
        )


def test_allows_normalizes_idna_and_rejects_malformed_hosts() -> None:
    scope = parse_scope_lines("xn--caf-dma.example")

    assert scope.allows("café.example.")
    assert not scope.allows("foo..example")
    assert not scope.allows(".xn--caf-dma.example")
    assert not scope.allows("192.0.2.1")


def test_parse_scope_rejects_mixed_valid_and_invalid_entries() -> None:
    with pytest.raises(ScopeError, match="line 2"):
        parse_scope_lines(["example.com", "https://bad.example.com"])


def test_parse_scope_requires_at_least_one_target() -> None:
    with pytest.raises(ScopeError, match="contains no targets"):
        parse_scope_lines(["", "# comment"])
