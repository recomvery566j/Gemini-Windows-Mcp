"""Smart output truncation and full-log bypass persistence."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path


class OutputGuard:
    """Limits inline output size and writes oversized logs to .tmp_outputs/."""

    def __init__(self, tmp_outputs_dir: Path, max_inline_chars: int = 16000,
                 head_chars: int = 4000, tail_chars: int = 4000):
        self.tmp_outputs_dir = tmp_outputs_dir
        self.max_inline_chars = max(1000, int(max_inline_chars))
        self.head_chars = max(200, int(head_chars))
        self.tail_chars = max(200, int(tail_chars))

    def format_or_bypass(self, text: str, prefix: str = "cmd") -> tuple[str, Path | None]:
        if len(text) <= self.max_inline_chars:
            return text, None

        self.tmp_outputs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = self.tmp_outputs_dir / f"{prefix}_{ts}_{uuid.uuid4().hex[:6]}.log"
        log_path.write_text(text, encoding="utf-8")

        head = text[:self.head_chars]
        tail = text[-self.tail_chars:]
        middle = text[self.head_chars:len(text) - self.tail_chars]
        omitted_lines = middle.count("\n")
        omitted_chars = len(middle)

        summary = (
            f"{head}\n\n"
            f"... [输出共 {len(text)} 字符，超出 {self.max_inline_chars} 字符上限；"
            f"已省略中间约 {omitted_lines} 行（{omitted_chars} 字符），完整日志已落盘：\n"
            f"{log_path}\n"
            f"如需查看中间细节，请使用 read_file 按 start_line / end_line 分段读取] ...\n\n"
            f"{tail}"
        )
        return summary, log_path
