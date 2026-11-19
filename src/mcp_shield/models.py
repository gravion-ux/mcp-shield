"""Core data types shared across mcp-shield."""

from dataclasses import asdict, dataclass

# Higher number = more severe. Used for sorting and --fail-on thresholds.
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITIES = tuple(SEVERITY_ORDER.keys())


@dataclass
class Finding:
    """A single audit finding."""

    check_id: str
    severity: str
    title: str
    location: str
    detail: str
    remediation: str

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError("unknown severity: %r" % (self.severity,))

    @property
    def severity_rank(self):
        return SEVERITY_ORDER[self.severity]

    def to_dict(self):
        return asdict(self)


def sort_findings(findings):
    """Most severe first, then by check id and location for stable output."""
    return sorted(
        findings,
        key=lambda f: (-f.severity_rank, f.check_id, f.location),
    )


def meets_threshold(finding, fail_on):
    """True if the finding is at or above the given severity name."""
    return finding.severity_rank >= SEVERITY_ORDER[fail_on]
