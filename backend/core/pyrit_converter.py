"""PyRIT PromptConverter 적용 유틸리티.

_ENCODING_DIRECTIVES의 mechanical 인덱스(2·3·4·9·10)에 대해
PyRIT 컨버터를 programmatic하게 적용한다.
language 기반 인덱스(0·1·5·6·7·8·11)는 LLM이 처리하므로 건드리지 않는다.

실행 환경: venv_pyrit (Python 3.13 + pyrit 설치됨)
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)

# PyRIT는 venv_pyrit (Python 3.13)에서만 설치돼 있음.
# venv (Python 3.9)에서 import 시 ImportError를 잡되, mechanical 인코딩이 필요한
# 인덱스에서 호출되면 시끄럽게 경고한다 (silent skip 방지).
try:
    from pyrit.prompt_converter import (
        Base64Converter,
        ROT13Converter,
        UnicodeConfusableConverter,
        BinaryConverter,
    )
    _PYRIT_AVAILABLE = True
except ImportError:
    _PYRIT_AVAILABLE = False
    logger.warning(
        "PyRIT not installed in current interpreter (%s). "
        "Mechanical encodings (base64/binary/unicode/rot13) will be skipped. "
        "Run SFT dataset generation with venv_pyrit/bin/python instead.",
        sys.executable,
    )

_warned_skipped: set[str] = set()

# _ENCODING_DIRECTIVES index → (converter_factory, description)
# None: LLM이 처리하는 language/structure 기반 → 컨버터 적용 안 함
_CONVERTER_MAP: dict[int, Optional[str]] = {
    0:  None,          # Korean framing
    1:  None,          # Chinese framing
    2:  "base64",      # base64 payload
    3:  "binary",      # hex/binary encoding
    4:  "unicode",     # Unicode homoglyphs
    5:  None,          # split payload (structure)
    6:  None,          # Japanese framing
    7:  None,          # Arabic framing
    8:  None,          # mixed Korean-English
    9:  "rot13",       # ROT13/Caesar
    10: "unicode",     # homoglyphs + base64 (unicode만 적용)
    11: None,          # Standard English, no encoding
}


async def _apply_async(converter_type: str, text: str) -> str:
    if converter_type == "base64":
        result = await Base64Converter().convert_async(prompt=text)
    elif converter_type == "rot13":
        result = await ROT13Converter().convert_async(prompt=text)
    elif converter_type == "unicode":
        result = await UnicodeConfusableConverter().convert_async(prompt=text)
    elif converter_type == "binary":
        result = await BinaryConverter().convert_async(prompt=text)
    else:
        return text
    return result.output_text


async def apply_pyrit_converter(text: str, encoding_index: int) -> tuple[str, str]:
    """PyRIT 컨버터를 적용한다.

    Returns:
        (converted_text, converter_name)  — 컨버터가 없으면 원문 그대로 반환
    """
    converter_type = _CONVERTER_MAP.get(encoding_index % len(_CONVERTER_MAP))
    if converter_type is None:
        return text, "none"

    if not _PYRIT_AVAILABLE:
        if converter_type not in _warned_skipped:
            _warned_skipped.add(converter_type)
            logger.warning(
                "PyRIT converter '%s' (encoding_index=%d) skipped because pyrit is not installed. "
                "Switch interpreter to venv_pyrit/bin/python to enable mechanical encoding.",
                converter_type, encoding_index,
            )
        return text, f"SKIPPED:{converter_type} (pyrit not installed)"

    converted = await _apply_async(converter_type, text)
    return converted, converter_type
