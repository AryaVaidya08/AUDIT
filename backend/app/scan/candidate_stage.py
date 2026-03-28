from __future__ import annotations

import ast
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Literal

from app.parse.chunkers import chunk_source
from app.scan.schema import CodeChunk, SourceFile

_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
_PYTHON_SUFFIX = ".py"
_JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
_REGION_CONTEXT_LINES = 12
_MERGE_REGION_GAP_LINES = 8
_JS_KEYWORDS = {
    "catch",
    "constructor",
    "do",
    "else",
    "for",
    "function",
    "if",
    "return",
    "switch",
    "try",
    "while",
}

_HIGH_SIGNAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:execute|executemany|query|raw_query|raw)\s*\("),
    re.compile(r"(?i)\b(?:select|insert|update|delete)\b"),
    re.compile(
        r"(?i)\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system|child_process\.(?:exec|spawn)|execSync|spawnSync)\b"
    ),
    re.compile(r"(?i)\b(?:eval|exec)\s*\("),
    re.compile(r"(?i)\bnew\s+Function\s*\("),
    re.compile(r"(?i)\b(?:pickle\.loads|yaml\.load|marshal\.loads|dill\.loads|unserialize)\s*\("),
    re.compile(
        r"(?i)\b(?:open|send_file|os\.path\.join|path\.join|fs\.(?:readFile|writeFile|createReadStream|createWriteStream))\s*\("
    ),
    re.compile(
        r"(?i)\b(?:render_template|render|res\.render|templateResponse|redirect|RedirectResponse|res\.redirect)\s*\("
    ),
    re.compile(
        r"(?i)\b(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|put|delete|request)|fetch|axios\.(?:get|post|put|delete|request)|urllib\.request|http\.request|https\.request)\s*\("
    ),
)
_ENTRYPOINT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?im)^\s*@\s*(?:app|router|bp|api)\.(?:get|post|put|patch|delete|route|websocket)\b"),
    re.compile(r"(?i)\b(?:app|router|server|api)\s*\.\s*(?:get|post|put|patch|delete|all|use|route|websocket)\s*\("),
    re.compile(r"(?i)\b(?:graphql|websocket|socket|middleware)\b"),
    re.compile(r"(?im)^\s*export\s+(?:default\s+)?(?:async\s+)?function\b"),
)
_AUTH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(?:auth|authorize|authorization|jwt|session|permission|permissions|role|roles|acl|rbac|is_admin|admin_required|login_required|require_auth|requireAuth|requireRole)\b"
    ),
)
_COARSE_RISK_PATTERNS: tuple[re.Pattern[str], ...] = _HIGH_SIGNAL_PATTERNS + _ENTRYPOINT_PATTERNS + _AUTH_PATTERNS
_ROUTE_HANDLER_PATTERN = re.compile(
    r"(?i)\b(?:app|router|server|api)\s*\.\s*(?P<method>get|post|put|patch|delete|all|use|route|websocket)\s*\("
)
_ARROW_FUNCTION_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^{=;]+)?=>\s*\{"
)
_FUNCTION_DECLARATION_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:export\s+default\s+|export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*"
    r"(?::[^{;=]+)?\{"
)
_EXPORTED_ANONYMOUS_FUNCTION_PATTERN = re.compile(r"(?m)^[ \t]*export\s+default\s+(?:async\s+)?function\b[^{]*\{")
_CLASS_PATTERN = re.compile(r"(?m)^[ \t]*(?:export\s+default\s+|export\s+)?class\s+[A-Za-z_$][\w$]*[^{]*\{")
_CLASS_METHOD_PATTERN = re.compile(r"(?m)^[ \t]*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}=]*\)\s*\{")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_$][\w$]*$")
_AUTH_NAME_WORDS = {"auth", "authorize", "authorization", "jwt", "session", "permission", "permissions", "role", "roles", "acl", "rbac", "admin"}


@dataclass(frozen=True)
class CandidateStageResult:
    scan_chunks: list[CodeChunk]
    backstop_chunks: list[CodeChunk]
    candidate_strategy: Literal["legacy_fixed_lines", "structured_hybrid_v1"]
    supported_files: int = 0
    regions_extracted: int = 0
    files_fallback: int = 0


@dataclass(frozen=True)
class _LineRegion:
    start_line: int
    end_line: int


@dataclass(frozen=True)
class _StructuredRegion:
    start_line: int
    end_line: int
    is_entrypoint: bool = False
    is_auth_surface: bool = False


@dataclass(frozen=True)
class _JSDelimiter:
    char: str
    index: int
    returns_to_template: bool = False


@dataclass(frozen=True)
class _JSLexResult:
    masked_text: str
    paren_pairs: dict[int, int]
    brace_pairs: dict[int, int]
    bracket_pairs: dict[int, int]
    line_starts: list[int]
    line_brace_depths: list[int]

    def line_number(self, index: int) -> int:
        return bisect_right(self.line_starts, max(index, 0))

    def line_brace_depth(self, index: int) -> int:
        line_number = max(1, self.line_number(index))
        depth_index = min(line_number - 1, len(self.line_brace_depths) - 1)
        return self.line_brace_depths[depth_index]


def build_scan_chunks(
    sources: list[SourceFile],
    *,
    chunk_size_lines: int,
    chunk_overlap_lines: int = 0,
    candidate_stage_enabled: bool = True,
) -> CandidateStageResult:
    backstop_chunks: list[CodeChunk] = []
    scan_chunks: list[CodeChunk] = []
    supported_files = 0
    regions_extracted = 0
    files_fallback = 0

    for source in sources:
        legacy_chunks = chunk_source(
            source=source,
            chunk_size_lines=chunk_size_lines,
            chunk_overlap_lines=chunk_overlap_lines,
        )
        backstop_chunks.extend(legacy_chunks)

        if not candidate_stage_enabled:
            scan_chunks.extend(legacy_chunks)
            continue

        suffix = Path(source.path).suffix.lower()
        if suffix not in _SUPPORTED_SUFFIXES:
            scan_chunks.extend(legacy_chunks)
            continue

        supported_files += 1
        try:
            extracted_regions = _extract_structured_regions(source)
        except ValueError:
            files_fallback += 1
            scan_chunks.extend(legacy_chunks)
            continue

        selected_regions = _select_candidate_regions(source, extracted_regions)
        if not selected_regions:
            if _has_coarse_risk_signal(source.text):
                files_fallback += 1
                scan_chunks.extend(legacy_chunks)
            continue

        merged_regions = _merge_expanded_regions(
            selected_regions,
            total_lines=len(source.text.splitlines()),
        )
        regions_extracted += len(merged_regions)
        for region in merged_regions:
            scan_chunks.extend(
                _chunk_region(
                    source=source,
                    start_line=region.start_line,
                    end_line=region.end_line,
                    chunk_size_lines=chunk_size_lines,
                    chunk_overlap_lines=chunk_overlap_lines,
                )
            )

    candidate_strategy: Literal["legacy_fixed_lines", "structured_hybrid_v1"]
    candidate_strategy = "structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines"
    return CandidateStageResult(
        scan_chunks=scan_chunks,
        backstop_chunks=backstop_chunks,
        candidate_strategy=candidate_strategy,
        supported_files=supported_files if candidate_stage_enabled else 0,
        regions_extracted=regions_extracted if candidate_stage_enabled else 0,
        files_fallback=files_fallback if candidate_stage_enabled else 0,
    )


def _extract_structured_regions(source: SourceFile) -> list[_StructuredRegion]:
    suffix = Path(source.path).suffix.lower()
    if suffix == _PYTHON_SUFFIX:
        return _extract_python_regions(source)
    if suffix in _JAVASCRIPT_SUFFIXES:
        return _extract_javascript_regions(source)
    return []


def _extract_python_regions(source: SourceFile) -> list[_StructuredRegion]:
    try:
        module = ast.parse(source.text)
    except SyntaxError as exc:
        raise ValueError(f"python_parse_error: {exc}") from exc

    regions: list[_StructuredRegion] = []
    for node in module.body:
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    regions.append(_python_node_region(child))
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            regions.append(_python_node_region(node))
            continue
        region = _python_stmt_region(node)
        if region is not None:
            regions.append(region)
    return _dedupe_structured_regions(regions)


def _python_node_region(node: ast.FunctionDef | ast.AsyncFunctionDef) -> _StructuredRegion:
    decorator_lines = [decorator.lineno for decorator in node.decorator_list if hasattr(decorator, "lineno")]
    start_line = min(decorator_lines + [node.lineno])
    end_line = getattr(node, "end_lineno", node.lineno)
    return _StructuredRegion(start_line=start_line, end_line=end_line)


def _python_stmt_region(node: ast.stmt) -> _StructuredRegion | None:
    if not hasattr(node, "lineno"):
        return None
    start_line = getattr(node, "lineno", None)
    end_line = getattr(node, "end_lineno", start_line)
    if start_line is None or end_line is None:
        return None
    return _StructuredRegion(start_line=int(start_line), end_line=int(end_line))


def _extract_javascript_regions(source: SourceFile) -> list[_StructuredRegion]:
    lex_result = _lex_javascript(source.text)
    masked_text = lex_result.masked_text
    regions: list[_StructuredRegion] = []
    named_handler_regions: dict[str, list[_StructuredRegion]] = {}

    for match in _FUNCTION_DECLARATION_PATTERN.finditer(masked_text):
        if lex_result.line_brace_depth(match.start()) != 0:
            continue
        open_brace = masked_text.find("{", match.start(), match.end())
        close_brace = lex_result.brace_pairs.get(open_brace)
        if open_brace < 0 or close_brace is None:
            continue
        name = match.group(1)
        region = _StructuredRegion(
            start_line=lex_result.line_number(match.start()),
            end_line=lex_result.line_number(close_brace),
            is_auth_surface=_name_has_auth_signal(name),
        )
        regions.append(region)
        named_handler_regions.setdefault(name, []).append(region)

    for match in _EXPORTED_ANONYMOUS_FUNCTION_PATTERN.finditer(masked_text):
        if lex_result.line_brace_depth(match.start()) != 0:
            continue
        open_brace = masked_text.find("{", match.start(), match.end())
        close_brace = lex_result.brace_pairs.get(open_brace)
        if open_brace < 0 or close_brace is None:
            continue
        regions.append(
            _StructuredRegion(
                start_line=lex_result.line_number(match.start()),
                end_line=lex_result.line_number(close_brace),
            )
        )

    for match in _ARROW_FUNCTION_PATTERN.finditer(masked_text):
        if lex_result.line_brace_depth(match.start()) != 0:
            continue
        open_brace = masked_text.find("{", match.start(), match.end())
        close_brace = lex_result.brace_pairs.get(open_brace)
        if open_brace < 0 or close_brace is None:
            continue
        name = match.group(1)
        region = _StructuredRegion(
            start_line=lex_result.line_number(match.start()),
            end_line=lex_result.line_number(close_brace),
            is_auth_surface=_name_has_auth_signal(name),
        )
        regions.append(region)
        named_handler_regions.setdefault(name, []).append(region)

    for match in _ROUTE_HANDLER_PATTERN.finditer(masked_text):
        open_paren = masked_text.find("(", match.start(), match.end())
        close_paren = lex_result.paren_pairs.get(open_paren)
        if open_paren < 0 or close_paren is None:
            continue
        regions.append(
            _StructuredRegion(
                start_line=lex_result.line_number(match.start()),
                end_line=lex_result.line_number(close_paren),
                is_entrypoint=True,
            )
        )
        method_name = match.group("method").lower()
        for handler_name in _extract_route_handler_names(
            masked_text=masked_text,
            open_paren=open_paren,
            close_paren=close_paren,
            method_name=method_name,
        ):
            for named_region in named_handler_regions.get(handler_name, []):
                regions.append(
                    _StructuredRegion(
                        start_line=named_region.start_line,
                        end_line=named_region.end_line,
                        is_entrypoint=True,
                        is_auth_surface=named_region.is_auth_surface,
                    )
                )

    for match in _CLASS_PATTERN.finditer(masked_text):
        if lex_result.line_brace_depth(match.start()) != 0:
            continue
        class_open_brace = masked_text.find("{", match.start(), match.end())
        class_close_brace = lex_result.brace_pairs.get(class_open_brace)
        if class_open_brace < 0 or class_close_brace is None:
            continue
        class_body = masked_text[class_open_brace + 1 : class_close_brace]
        for method_match in _CLASS_METHOD_PATTERN.finditer(class_body):
            method_name = method_match.group(1)
            if method_name in _JS_KEYWORDS:
                continue
            global_start = class_open_brace + 1 + method_match.start()
            if lex_result.line_brace_depth(global_start) != 1:
                continue
            method_open_brace = class_open_brace + 1 + method_match.end() - 1
            if method_open_brace not in lex_result.brace_pairs:
                continue
            regions.append(
                _StructuredRegion(
                    start_line=lex_result.line_number(global_start),
                    end_line=lex_result.line_number(lex_result.brace_pairs[method_open_brace]),
                    is_auth_surface=_name_has_auth_signal(method_name),
                )
            )

    return _dedupe_structured_regions(regions)


def _lex_javascript(text: str) -> _JSLexResult:
    chars = list(text)
    masked = chars[:]
    delimiter_stack: list[_JSDelimiter] = []
    paren_pairs: dict[int, int] = {}
    brace_pairs: dict[int, int] = {}
    bracket_pairs: dict[int, int] = {}
    line_starts = [0]
    line_brace_depths = [0]
    index = 0
    length = len(chars)
    state = "code"
    brace_depth = 0

    while index < length:
        char = chars[index]

        if state == "code":
            if char == "/" and index + 1 < length and chars[index + 1] == "/":
                masked[index] = " "
                masked[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and index + 1 < length and chars[index + 1] == "*":
                masked[index] = " "
                masked[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == "'":
                masked[index] = " "
                state = "single_quote"
                index += 1
                continue
            if char == '"':
                masked[index] = " "
                state = "double_quote"
                index += 1
                continue
            if char == "`":
                masked[index] = " "
                state = "template"
                index += 1
                continue
            if char == "(":
                delimiter_stack.append(_JSDelimiter(char=char, index=index))
            elif char == "[":
                delimiter_stack.append(_JSDelimiter(char=char, index=index))
            elif char == "{":
                delimiter_stack.append(_JSDelimiter(char=char, index=index))
                brace_depth += 1
            elif char in {")", "]", "}"}:
                if not delimiter_stack:
                    raise ValueError(f"javascript_parse_error: unmatched closing delimiter {char}")
                open_delimiter = delimiter_stack.pop()
                expected = {")": "(", "]": "[", "}": "{"}[char]
                if open_delimiter.char != expected:
                    raise ValueError(f"javascript_parse_error: mismatched closing delimiter {char}")
                if char == ")":
                    paren_pairs[open_delimiter.index] = index
                elif char == "]":
                    bracket_pairs[open_delimiter.index] = index
                else:
                    brace_pairs[open_delimiter.index] = index
                    brace_depth -= 1
                    if open_delimiter.returns_to_template:
                        state = "template"
            if char == "\n":
                line_starts.append(index + 1)
                line_brace_depths.append(brace_depth)
            index += 1
            continue

        if state == "line_comment":
            masked[index] = "\n" if char == "\n" else " "
            if char == "\n":
                line_starts.append(index + 1)
                line_brace_depths.append(brace_depth)
                state = "code"
            index += 1
            continue

        if state == "block_comment":
            masked[index] = "\n" if char == "\n" else " "
            if char == "\n":
                line_starts.append(index + 1)
                line_brace_depths.append(brace_depth)
            if char == "*" and index + 1 < length and chars[index + 1] == "/":
                masked[index + 1] = " "
                state = "code"
                index += 2
                continue
            index += 1
            continue

        if state == "template" and char == "$" and index + 1 < length and chars[index + 1] == "{":
            masked[index] = " "
            masked[index + 1] = "{"
            delimiter_stack.append(_JSDelimiter(char="{", index=index + 1, returns_to_template=True))
            brace_depth += 1
            state = "code"
            index += 2
            continue

        masked[index] = "\n" if char == "\n" else " "
        if char == "\n":
            line_starts.append(index + 1)
            line_brace_depths.append(brace_depth)
        if char == "\\" and index + 1 < length:
            masked[index + 1] = "\n" if chars[index + 1] == "\n" else " "
            if chars[index + 1] == "\n":
                line_starts.append(index + 2)
                line_brace_depths.append(brace_depth)
            index += 2
            continue
        if state == "single_quote" and char == "'":
            state = "code"
        elif state == "double_quote" and char == '"':
            state = "code"
        elif state == "template" and char == "`":
            state = "code"
        index += 1

    if state != "code":
        raise ValueError(f"javascript_parse_error: unterminated {state}")
    if delimiter_stack:
        opening = delimiter_stack[-1].char
        raise ValueError(f"javascript_parse_error: unmatched opening delimiter {opening}")

    return _JSLexResult(
        masked_text="".join(masked),
        paren_pairs=paren_pairs,
        brace_pairs=brace_pairs,
        bracket_pairs=bracket_pairs,
        line_starts=line_starts,
        line_brace_depths=line_brace_depths,
    )


def _extract_route_handler_names(
    *,
    masked_text: str,
    open_paren: int,
    close_paren: int,
    method_name: str,
) -> list[str]:
    names: list[str] = []
    skip_first_argument = method_name not in {"use"}
    for argument_index, (start_index, end_index) in enumerate(
        _iter_top_level_argument_spans(masked_text=masked_text, open_paren=open_paren, close_paren=close_paren)
    ):
        if skip_first_argument and argument_index == 0:
            continue
        argument = masked_text[start_index:end_index].strip()
        if not argument:
            continue
        if _IDENTIFIER_PATTERN.fullmatch(argument):
            names.append(argument)
    return names


def _iter_top_level_argument_spans(*, masked_text: str, open_paren: int, close_paren: int) -> list[tuple[int, int]]:
    argument_spans: list[tuple[int, int]] = []
    argument_start = open_paren + 1
    paren_depth = 0
    brace_depth = 0
    bracket_depth = 0

    for index in range(open_paren + 1, close_paren):
        char = masked_text[index]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "," and paren_depth == 0 and brace_depth == 0 and bracket_depth == 0:
            trimmed_span = _trim_span(masked_text=masked_text, start_index=argument_start, end_index=index)
            if trimmed_span is not None:
                argument_spans.append(trimmed_span)
            argument_start = index + 1

    final_span = _trim_span(masked_text=masked_text, start_index=argument_start, end_index=close_paren)
    if final_span is not None:
        argument_spans.append(final_span)
    return argument_spans


def _trim_span(*, masked_text: str, start_index: int, end_index: int) -> tuple[int, int] | None:
    left = start_index
    right = end_index
    while left < right and masked_text[left].isspace():
        left += 1
    while right > left and masked_text[right - 1].isspace():
        right -= 1
    if left >= right:
        return None
    return left, right


def _select_candidate_regions(source: SourceFile, regions: list[_StructuredRegion]) -> list[_LineRegion]:
    lines = source.text.splitlines()
    selected: list[_LineRegion] = []
    for region in regions:
        if region.start_line < 1 or region.end_line < region.start_line:
            continue
        if not lines:
            continue
        end_line = min(region.end_line, len(lines))
        start_line = min(region.start_line, end_line)
        snippet = "\n".join(lines[start_line - 1 : end_line]).strip()
        if not snippet:
            continue
        if region.is_entrypoint or region.is_auth_surface or _has_candidate_signal(snippet):
            selected.append(_LineRegion(start_line=start_line, end_line=end_line))
    return _dedupe_regions(selected)


def _has_candidate_signal(text: str) -> bool:
    return any(pattern.search(text) for pattern in _COARSE_RISK_PATTERNS)


def _has_coarse_risk_signal(text: str) -> bool:
    return any(pattern.search(text) for pattern in _COARSE_RISK_PATTERNS)


def _merge_expanded_regions(regions: list[_LineRegion], *, total_lines: int) -> list[_LineRegion]:
    if not regions or total_lines <= 0:
        return []

    expanded = sorted(
        (
            _LineRegion(
                start_line=max(1, region.start_line - _REGION_CONTEXT_LINES),
                end_line=min(total_lines, region.end_line + _REGION_CONTEXT_LINES),
            )
            for region in regions
        ),
        key=lambda item: (item.start_line, item.end_line),
    )

    merged: list[_LineRegion] = [expanded[0]]
    for region in expanded[1:]:
        current = merged[-1]
        if region.start_line <= current.end_line + _MERGE_REGION_GAP_LINES + 1:
            merged[-1] = _LineRegion(
                start_line=current.start_line,
                end_line=max(current.end_line, region.end_line),
            )
            continue
        merged.append(region)
    return merged


def _chunk_region(
    *,
    source: SourceFile,
    start_line: int,
    end_line: int,
    chunk_size_lines: int,
    chunk_overlap_lines: int,
) -> list[CodeChunk]:
    lines = source.text.splitlines()
    if not lines:
        return []
    region_lines = lines[start_line - 1 : end_line]
    if not region_lines:
        return []

    overlap = min(max(chunk_overlap_lines, 0), chunk_size_lines - 1)
    step = chunk_size_lines - overlap if overlap > 0 else chunk_size_lines

    chunks: list[CodeChunk] = []
    for offset in range(0, len(region_lines), step):
        chunk_lines = region_lines[offset : offset + chunk_size_lines]
        if not chunk_lines:
            continue
        chunk_start_line = start_line + offset
        chunk_end_line = min(chunk_start_line + len(chunk_lines) - 1, end_line)
        chunks.append(
            CodeChunk(
                file_path=source.path,
                start_line=chunk_start_line,
                end_line=chunk_end_line,
                text="\n".join(chunk_lines),
            )
        )
        if chunk_end_line >= end_line:
            break
    return chunks


def _name_has_auth_signal(name: str) -> bool:
    if _has_auth_signal(name):
        return True
    normalized = " ".join(_split_identifier_words(name))
    if not normalized:
        return False
    return any(pattern.search(normalized) for pattern in _AUTH_PATTERNS) or any(
        word in _AUTH_NAME_WORDS for word in normalized.split()
    )


def _has_auth_signal(text: str) -> bool:
    return any(pattern.search(text) for pattern in _AUTH_PATTERNS)


def _split_identifier_words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"[_\-]+", " ", spaced)
    return [part.lower() for part in spaced.split() if part]


def _dedupe_structured_regions(regions: list[_StructuredRegion]) -> list[_StructuredRegion]:
    merged_by_span: dict[tuple[int, int], _StructuredRegion] = {}
    for region in sorted(regions, key=lambda item: (item.start_line, item.end_line)):
        key = (region.start_line, region.end_line)
        existing = merged_by_span.get(key)
        if existing is None:
            merged_by_span[key] = region
            continue
        merged_by_span[key] = _StructuredRegion(
            start_line=region.start_line,
            end_line=region.end_line,
            is_entrypoint=existing.is_entrypoint or region.is_entrypoint,
            is_auth_surface=existing.is_auth_surface or region.is_auth_surface,
        )
    return list(merged_by_span.values())


def _dedupe_regions(regions: list[_LineRegion]) -> list[_LineRegion]:
    deduped: list[_LineRegion] = []
    seen: set[tuple[int, int]] = set()
    for region in sorted(regions, key=lambda item: (item.start_line, item.end_line)):
        key = (region.start_line, region.end_line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(region)
    return deduped
