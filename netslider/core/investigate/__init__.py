"""R2 investigation: action-log alignment, framing probes, compare."""

from netslider.core.investigate.action_log import ActionEvent, ActionLog, load_action_log
from netslider.core.investigate.align import AlignedAction, align_actions
from netslider.core.investigate.compare import RangeDiff, diff_ranges
from netslider.core.investigate.framing import (
    DelimiterStats,
    LengthPrefixProbe,
    MagicHit,
    delimiter_histogram,
    find_magic,
    parse_magic_string,
    probe_grid,
    probe_length_prefix,
)

__all__ = [
    "ActionEvent",
    "ActionLog",
    "AlignedAction",
    "DelimiterStats",
    "LengthPrefixProbe",
    "MagicHit",
    "RangeDiff",
    "align_actions",
    "delimiter_histogram",
    "diff_ranges",
    "find_magic",
    "load_action_log",
    "parse_magic_string",
    "probe_grid",
    "probe_length_prefix",
]
