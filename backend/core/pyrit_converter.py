"""PyRIT PromptConverter 적용 유틸리티.

_ENCODING_DIRECTIVES의 mechanical 인덱스(2·3·4·9·10)에 대해
PyRIT 컨버터를 programmatic하게 적용한다.
language 기반 인덱스(0·1·5·6·7·8·11)는 LLM이 처리하므로 건드리지 않는다.

실행 환경: venv_pyrit (Python 3.13 + pyrit 설치됨)
"""

from __future__ import annotations

import asyncio
from typing import Optional

# PyRIT가 없는 환경(venv, Python 3.9)에서 import해도 오류 안 남
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


def apply_pyrit_converter(text: str, encoding_index: int) -> tuple[str, str]:
    """PyRIT 컨버터를 적용한다.

    Returns:
        (converted_text, converter_name)  — 컨버터가 없으면 원문 그대로 반환
    """
    if not _PYRIT_AVAILABLE:
        return text, "none (pyrit not installed)"

    converter_type = _CONVERTER_MAP.get(encoding_index % len(_CONVERTER_MAP))
    if converter_type is None:
        return text, "none"

    converted = asyncio.run(_apply_async(converter_type, text))
    return converted, converter_type
