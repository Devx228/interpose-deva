from __future__ import annotations

from collections.abc import Iterable

from capgate.taint.labels import BOTTOM_LABEL, Label


def join_labels(labels: Iterable[Label]) -> Label:
    joined = BOTTOM_LABEL
    for label in labels:
        joined = joined.join(label)
    return joined


def propagate_tool_result(argument_label: Label, source_label: Label) -> Label:
    return argument_label.join(source_label)
