from capgate.policy.confinement import is_monotonic_narrowing
from capgate.policy.dsl import load_policy, parse_policy
from capgate.policy.enforce import enforce
from capgate.policy.model import Capability, CapabilityPattern, Policy, PolicyError

__all__ = [
    "Capability",
    "CapabilityPattern",
    "Policy",
    "PolicyError",
    "enforce",
    "is_monotonic_narrowing",
    "load_policy",
    "parse_policy",
]
