from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Iterable


DEFAULT_CATEGORIES: tuple[str, ...] = (
    "paediatrics",
    "adults",
    "women",
    "pharmacology",
    "lab",
    "imaging",
)

ALLOWED_EXTENSIONS: tuple[str, ...] = (".pdf", ".txt", ".md", ".docx")


def is_allowed_book_file(path: Path) -> bool:
    try:
        return path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_pdf(path: Path) -> str:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("PDF extraction requires the optional dependency: pypdf") from e

    reader = PdfReader(str(path))
    parts: list[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            parts.append("")
    return "\n".join([p for p in parts if p])


def _read_docx(path: Path) -> str:
    try:
        import docx  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("DOCX extraction requires the optional dependency: python-docx") from e

    d = docx.Document(str(path))
    parts = []
    for p in d.paragraphs:
        t = (p.text or "").strip()
        if t:
            parts.append(t)
    return "\n".join(parts)


def extract_book_text(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in (".txt", ".md"):
        return _read_text(path)
    if ext == ".pdf":
        return _read_pdf(path)
    if ext == ".docx":
        return _read_docx(path)
    raise ValueError(f"Unsupported book file type: {ext}")


def chunk_text(text: str, *, chunk_chars: int = 1800, overlap: int = 250) -> list[str]:
    s = (text or "").strip()
    if not s:
        return []
    chunk_chars = max(400, int(chunk_chars))
    overlap = max(0, min(int(overlap), chunk_chars // 2))

    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        end = min(n, i + chunk_chars)
        chunk = s[i:end].strip()
        if chunk:
            out.append(chunk)
        if end >= n:
            break
        i = max(0, end - overlap)
    return out


@dataclass(frozen=True)
class KBStats:
    processed_at: str
    files: int
    chunks: int
    errors: list[str]

    def to_dict(self) -> dict:
        return {
            "processed_at": self.processed_at,
            "files": self.files,
            "chunks": self.chunks,
            "errors": list(self.errors or []),
        }


def iter_book_files(root: Path, *, categories: Iterable[str] = DEFAULT_CATEGORIES) -> Iterable[tuple[str, Path]]:
    for cat in categories:
        cat_dir = root / cat
        if not cat_dir.exists():
            continue
        for p in cat_dir.rglob("*"):
            if is_allowed_book_file(p):
                yield cat, p


def build_kb_index(*, books_root: Path, out_index_path: Path, out_meta_path: Path | None = None) -> KBStats:
    books_root = Path(books_root)
    out_index_path = Path(out_index_path)
    if out_meta_path is not None:
        out_meta_path = Path(out_meta_path)

    out_index_path.parent.mkdir(parents=True, exist_ok=True)
    if out_meta_path is not None:
        out_meta_path.parent.mkdir(parents=True, exist_ok=True)

    chunks_out: list[dict] = []
    errors: list[str] = []
    files_count = 0

    for category, path in iter_book_files(books_root):
        files_count += 1
        try:
            text = extract_book_text(path)
            file_sha = sha256_file(path)
            chunks = chunk_text(text)
            for idx, c in enumerate(chunks):
                chunks_out.append(
                    {
                        "category": category,
                        "source_file": str(path.relative_to(books_root)).replace("\\", "/"),
                        "sha256": file_sha,
                        "chunk_index": idx,
                        "text": c,
                    }
                )
        except Exception as e:
            errors.append(f"{category}/{path.name}: {type(e).__name__}: {e}")

    payload = {
        "version": 1,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "chunks": chunks_out,
    }
    out_index_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    stats = KBStats(
        processed_at=datetime.utcnow().isoformat() + "Z",
        files=files_count,
        chunks=len(chunks_out),
        errors=errors,
    )

    if out_meta_path is not None:
        out_meta_path.write_text(json.dumps(stats.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    return stats


# ---------------------------
# Retrieval (Doctor Agent)
# ---------------------------

_KB_CACHE: dict[str, object] = {
    "index_path": None,
    "payload": None,
    "chunks": None,
    "chunks_lower": None,
    "loaded_at": None,
}


def _default_instance_dir() -> Path:
    try:
        from flask import current_app  # type: ignore

        return Path(getattr(current_app, "instance_path", "instance"))
    except Exception:
        return Path("instance")


def default_kb_index_path() -> Path:
    return _default_instance_dir() / "doctor_agent_kb.json"


def default_kb_meta_path() -> Path:
    return _default_instance_dir() / "doctor_agent_kb_meta.json"


def refresh_kb_cache(*, index_path: Path | None = None) -> None:
    """Clear any in-memory KB cache. Next retrieval reloads from disk."""
    global _KB_CACHE
    _KB_CACHE = {
        "index_path": str(index_path) if index_path is not None else None,
        "payload": None,
        "chunks": None,
        "chunks_lower": None,
        "loaded_at": None,
    }


def _load_kb_payload(*, index_path: Path | None = None) -> dict | None:
    path = Path(index_path) if index_path is not None else default_kb_index_path()
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return None
        if "chunks" not in payload or not isinstance(payload.get("chunks"), list):
            return None
        return payload
    except Exception:
        return None


def get_kb_chunks(*, index_path: Path | None = None) -> list[dict]:
    """Load KB chunks with a tiny in-process cache."""
    global _KB_CACHE
    resolved = str(Path(index_path) if index_path is not None else default_kb_index_path())

    if _KB_CACHE.get("chunks") is not None and str(_KB_CACHE.get("index_path") or resolved) == resolved:
        chunks = _KB_CACHE.get("chunks")
        return list(chunks) if isinstance(chunks, list) else []

    payload = _load_kb_payload(index_path=Path(resolved))
    chunks = payload.get("chunks") if isinstance(payload, dict) else None
    if not isinstance(chunks, list):
        chunks = []

    _KB_CACHE["index_path"] = resolved
    _KB_CACHE["payload"] = payload
    _KB_CACHE["chunks"] = chunks
    _KB_CACHE["chunks_lower"] = [str(c.get("text") or "").lower() for c in chunks] if chunks else []
    _KB_CACHE["loaded_at"] = datetime.utcnow().isoformat() + "Z"
    return chunks


_STOPWORDS: set[str] = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "but",
    "by",
    "for",
    "from",
    "has",
    "have",
    "he",
    "her",
    "hers",
    "him",
    "his",
    "i",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "our",
    "she",
    "that",
    "the",
    "their",
    "them",
    "they",
    "this",
    "to",
    "was",
    "were",
    "with",
    "without",
    "you",
    "your",
}


def _tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]{3,}", (text or "").lower())
    out: list[str] = []
    for t in tokens:
        if t in _STOPWORDS:
            continue
        if len(t) < 3:
            continue
        out.append(t)
    # De-dup while preserving order
    seen = set()
    uniq = []
    for t in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    return uniq[:40]


def resolve_kb_categories(*, age_years: int | float | None, gender: str | None, domain: str) -> tuple[str, ...]:
    """Route which uploaded books are eligible for retrieval.

    domain:
      - general|diagnosis|summary|hpi|ros|exam|management
      - obgyn
      - lab
      - imaging
      - pharmacology
    """
    d = (domain or "").strip().lower()
    g = (gender or "").strip().lower()
    try:
        age_val = float(age_years) if age_years is not None else None
    except Exception:
        age_val = None

    if d in {"lab"}:
        return ("lab", "adults")
    if d in {"imaging"}:
        return ("imaging",)
    if d in {"drug", "drugs", "pharmacology", "treatment"}:
        return ("pharmacology",)
    if d in {"obgyn", "obstetrics", "gynaecology", "gynecology"}:
        return ("women",)

    # General clinical domains
    if age_val is not None and age_val < 18:
        return ("paediatrics",)
    if g.startswith("f"):
        # Adult female: include both adults and women; prompt can constrain OB/GYN usage.
        return ("adults", "women")
    return ("adults",)


def retrieve_kb_snippets(
    query: str,
    *,
    categories: Iterable[str] | None = None,
    k: int = 6,
    max_chars_per_snippet: int = 900,
    index_path: Path | None = None,
) -> list[dict]:
    """Return best-effort KB snippets for prompt grounding.

    No embeddings: uses simple keyword matching with lightweight scoring.
    """
    chunks = get_kb_chunks(index_path=index_path)
    chunks_lower = _KB_CACHE.get("chunks_lower")
    if not isinstance(chunks_lower, list):
        chunks_lower = [str(c.get("text") or "").lower() for c in chunks]

    tokens = _tokenize(query)
    if not tokens:
        return []

    catset = None
    if categories is not None:
        catset = {str(c).strip().lower() for c in categories if str(c).strip()}

    scored: list[tuple[float, int]] = []
    for i, c in enumerate(chunks):
        try:
            if catset is not None:
                cc = str(c.get("category") or "").strip().lower()
                if cc not in catset:
                    continue
            text_l = chunks_lower[i] if i < len(chunks_lower) else str(c.get("text") or "").lower()
            if not text_l:
                continue

            score = 0.0
            for t in tokens:
                if t in text_l:
                    score += 1.0
                    # Reward repeated hits a bit, but cap to avoid spammy tokens.
                    score += min(3, text_l.count(t)) * 0.15
            if score <= 0:
                continue
            scored.append((score, i))
        except Exception:
            continue

    if not scored:
        return []

    scored.sort(key=lambda x: x[0], reverse=True)
    out: list[dict] = []
    seen_sources: set[str] = set()
    for score, idx in scored[: max(k * 3, k)]:
        c = chunks[idx]
        source = str(c.get("source_file") or "")
        if source and source in seen_sources:
            continue
        seen_sources.add(source)

        text = str(c.get("text") or "").strip()
        if max_chars_per_snippet and len(text) > max_chars_per_snippet:
            text = text[: max_chars_per_snippet - 3].rstrip() + "..."
        out.append(
            {
                "category": c.get("category"),
                "source_file": c.get("source_file"),
                "chunk_index": c.get("chunk_index"),
                "sha256": c.get("sha256"),
                "score": float(score),
                "text": text,
            }
        )
        if len(out) >= int(k):
            break
    return out
