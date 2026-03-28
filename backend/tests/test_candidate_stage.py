from __future__ import annotations

from app.scan.candidate_stage import build_scan_chunks
from app.scan.schema import SourceFile


def test_build_scan_chunks_extracts_python_route_auth_and_module_regions() -> None:
    filler = "\n".join([f"print({index})" for index in range(35)])
    source = SourceFile(
        path="src/app.py",
        text=(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n\n"
            '@router.get("/admin/users")\n'
            "def list_users(user_id: str):\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    return conn.execute(query).fetchall()\n\n"
            f"{filler}\n\n"
            "def require_auth(token: str):\n"
            "    return verify(token)\n\n"
            f"{filler}\n\n"
            "result = eval(user_input)\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=120, candidate_stage_enabled=True)

    assert result.candidate_strategy == "structured_hybrid_v1"
    assert result.supported_files == 1
    assert result.files_fallback == 0
    assert result.regions_extracted == 3
    joined_chunks = "\n---\n".join(chunk.text for chunk in result.scan_chunks)
    assert '@router.get("/admin/users")' in joined_chunks
    assert "require_auth" in joined_chunks
    assert "result = eval(user_input)" in joined_chunks


def test_build_scan_chunks_splits_large_python_regions() -> None:
    body = "\n".join([f"    print({index})" for index in range(60)])
    source = SourceFile(
        path="src/worker.py",
        text=(
            "def run_query(user_id):\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    conn.execute(query)\n"
            f"{body}\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=20, candidate_stage_enabled=True)

    assert result.files_fallback == 0
    assert result.regions_extracted == 1
    assert len(result.scan_chunks) > 1
    assert result.scan_chunks[0].start_line == 1
    assert result.scan_chunks[-1].end_line > 20


def test_build_scan_chunks_falls_back_on_python_syntax_error() -> None:
    source = SourceFile(
        path="src/broken.py",
        text="def broken(:\n    return eval(user_input)\n",
    )

    result = build_scan_chunks([source], chunk_size_lines=20, candidate_stage_enabled=True)

    assert result.supported_files == 1
    assert result.files_fallback == 1
    assert result.regions_extracted == 0
    assert len(result.scan_chunks) == 1
    assert "eval(user_input)" in result.scan_chunks[0].text


def test_build_scan_chunks_extracts_js_route_arrow_and_class_method_regions() -> None:
    filler = "\n".join([f"console.log({index});" for index in range(35)])
    source = SourceFile(
        path="src/routes.js",
        text=(
            "const express = require(\"express\");\n"
            "const app = express();\n\n"
            'app.get("/admin/users", (req, res) => {\n'
            "  // braces in comments should not change region parsing {}\n"
            '  const msg = "{not a brace}";\n'
            '  const payload = `${JSON.stringify({ ok: true })}`;\n'
            "  res.json({ ok: true });\n"
            "});\n\n"
            f"{filler}\n\n"
            "const loadProfile = async (url) => {\n"
            "  return fetch(url);\n"
            "};\n\n"
            f"{filler}\n\n"
            "class UserController {\n"
            "  renderUser(req, res) {\n"
            "    return res.render(\"user\");\n"
            "  }\n"
            "}\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=120, candidate_stage_enabled=True)

    assert result.candidate_strategy == "structured_hybrid_v1"
    assert result.supported_files == 1
    assert result.files_fallback == 0
    assert result.regions_extracted == 3
    joined_chunks = "\n---\n".join(chunk.text for chunk in result.scan_chunks)
    assert 'app.get("/admin/users"' in joined_chunks
    assert "return fetch(url);" in joined_chunks
    assert 'return res.render("user");' in joined_chunks


def test_build_scan_chunks_maps_js_named_route_handlers_to_the_real_function_region() -> None:
    filler = "\n".join([f"console.log({index});" for index in range(18)])
    source = SourceFile(
        path="src/routes.js",
        text=(
            "const express = require(\"express\");\n"
            "const app = express();\n\n"
            'app.get("/admin/users", listUsers);\n\n'
            f"{filler}\n\n"
            "function helper() {\n"
            "  return true;\n"
            "}\n\n"
            f"{filler}\n\n"
            "function listUsers(req, res) {\n"
            "  const query = `SELECT * FROM users`;\n"
            "  return db.query(query);\n"
            "}\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=120, candidate_stage_enabled=True)

    assert result.supported_files == 1
    assert result.files_fallback == 0
    assert result.regions_extracted == 2
    joined_chunks = "\n---\n".join(chunk.text for chunk in result.scan_chunks)
    assert 'app.get("/admin/users", listUsers);' in joined_chunks
    assert "function listUsers(req, res)" in joined_chunks
    assert "return db.query(query);" in joined_chunks
    assert "function helper()" not in joined_chunks


def test_build_scan_chunks_keeps_long_js_route_callback_bodies_inside_the_route_region() -> None:
    long_schema = ",\n".join([f'      field{index}: "{("x" * 48)}"' for index in range(30)])
    source = SourceFile(
        path="src/routes.js",
        text=(
            "const express = require(\"express\");\n"
            "const app = express();\n\n"
            'app.get("/admin/users", {\n'
            "  schema: {\n"
            f"{long_schema}\n"
            "  }\n"
            "}, async function(req, res) {\n"
            '  const payload = `${JSON.stringify({ nested: { ok: true } })}`;\n'
            "  // braces in comments should be ignored {}\n"
            "  return fetch(req.query.url);\n"
            "});\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=120, candidate_stage_enabled=True)

    assert result.supported_files == 1
    assert result.files_fallback == 0
    assert result.regions_extracted == 1
    joined_chunks = "\n---\n".join(chunk.text for chunk in result.scan_chunks)
    assert 'app.get("/admin/users", {' in joined_chunks
    assert "return fetch(req.query.url);" in joined_chunks


def test_build_scan_chunks_keeps_plain_js_auth_helpers_without_file_level_fallback() -> None:
    filler = "\n".join([f"console.log({index});" for index in range(40)])
    source = SourceFile(
        path="src/auth.js",
        text=(
            "const loadProfile = async (url) => {\n"
            "  return fetch(url);\n"
            "};\n\n"
            f"{filler}\n\n"
            "function hasPermission(user, role) {\n"
            "  return user.roles.includes(role);\n"
            "}\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=120, candidate_stage_enabled=True)

    assert result.supported_files == 1
    assert result.files_fallback == 0
    assert result.regions_extracted == 2
    joined_chunks = "\n---\n".join(chunk.text for chunk in result.scan_chunks)
    assert "return fetch(url);" in joined_chunks
    assert "function hasPermission(user, role)" in joined_chunks


def test_build_scan_chunks_falls_back_on_malformed_javascript() -> None:
    source = SourceFile(
        path="src/broken.js",
        text=(
            'app.get("/admin", (req, res) => {\n'
            "  return fetch(url);\n"
        ),
    )

    result = build_scan_chunks([source], chunk_size_lines=20, candidate_stage_enabled=True)

    assert result.supported_files == 1
    assert result.files_fallback == 1
    assert result.regions_extracted == 0
    assert len(result.scan_chunks) == 1
    assert 'app.get("/admin"' in result.scan_chunks[0].text
