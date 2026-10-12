"""Declarative + Python interpretation engine (Phase 3)."""

from madrigal.core.interp.apply import (
    apply_declarative,
    apply_interpretation_file,
    apply_interpretation_text,
    interpretation_hash_for_path,
)
from madrigal.core.interp.models import (
    ApplyResult,
    ApplyStats,
    FieldValue,
    MessageSpan,
    ParsedMessage,
    ProvenanceRef,
    ValueStatus,
)
from madrigal.core.interp.python_hook import PythonHookError, apply_python_script
from madrigal.core.interp.schema import (
    DEMO_DEVICE_V1_YAML,
    InterpretationDoc,
    SchemaError,
    load_interpretation,
    parse_interpretation_text,
)

__all__ = [
    "ApplyResult",
    "ApplyStats",
    "DEMO_DEVICE_V1_YAML",
    "FieldValue",
    "InterpretationDoc",
    "MessageSpan",
    "ParsedMessage",
    "ProvenanceRef",
    "PythonHookError",
    "SchemaError",
    "ValueStatus",
    "apply_declarative",
    "apply_interpretation_file",
    "apply_interpretation_text",
    "apply_python_script",
    "interpretation_hash_for_path",
    "load_interpretation",
    "parse_interpretation_text",
]
