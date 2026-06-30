from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Confidentiality(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SECRET = "secret"


class Integrity(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


_CONFIDENTIALITY_RANK = {
    Confidentiality.PUBLIC: 0,
    Confidentiality.INTERNAL: 1,
    Confidentiality.SECRET: 2,
}


@dataclass(frozen=True)
class Label:
    confidentiality: Confidentiality
    integrity: Integrity
    source_tags: frozenset[str] = frozenset()

    def join(self, other: Label) -> Label:
        confidentiality = max(
            self.confidentiality,
            other.confidentiality,
            key=_CONFIDENTIALITY_RANK.__getitem__,
        )
        integrity = (
            Integrity.UNTRUSTED
            if Integrity.UNTRUSTED in {self.integrity, other.integrity}
            else Integrity.TRUSTED
        )
        return Label(
            confidentiality=confidentiality,
            integrity=integrity,
            source_tags=self.source_tags | other.source_tags,
        )


BOTTOM_LABEL = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)
