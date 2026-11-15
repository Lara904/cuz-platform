# packages/remediation/terraform_edit.py
"""Édition HCL minimale et déterministe d'un bloc `resource` EXISTANT (P2.10).

On ne génère pas de code Terraform « libre » : on modifie un attribut précis d'une ressource déjà écrite
dans le dépôt IaC, ce qui donne un diff minimal, relisable et prévisible. Seul texte inséré : une constante
(`acl = "private"`) ; rien de ce qui vient d'un finding (nom d'actif, titre...) n'est jamais écrit dans le
code HCL, il ne sert qu'à LOCALISER la ressource.

Analyse volontairement simple (chaînes, commentaires `#` `//` `/* */`, heredocs, profondeur d'accolades).
Tout ce qu'elle ne comprend pas mène à un REFUS explicite, jamais à une modification devinée : fichier non
analysable, ressource introuvable ou ambiguë, valeur non littérale, ressource déjà conforme.
"""

import difflib
import re
from dataclasses import dataclass


class HCLError(Exception):
    """Fichier non analysable avec ce lexeur minimal (accolades déséquilibrées, ...)."""


class NonLiteralValueError(Exception):
    pass


class AlreadyPrivateError(Exception):
    pass


class AlreadyClosedError(Exception):
    """P2.10 bis : le CIDR 0.0.0.0/0 n'est plus présent, l'écart est côté infra, pas le code."""


@dataclass(frozen=True)
class ResourceBlock:
    type: str
    name: str
    start: int  # index de `resource`
    body_start: int  # index juste après `{`
    end: int  # index du `}` fermant


@dataclass(frozen=True)
class TerraformEdit:
    before: str
    after: str
    block: ResourceBlock

    def diff(self, path: str) -> str:
        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
            )
        )


_HEREDOC = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)")
_HEADER = re.compile(r'(?:^|\n)[ \t]*resource[ \t]+"([^"\n]+)"[ \t]+"([^"\n]+)"[ \t]*$')
_ATTRIBUTE = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_-]*)[ \t]*=[ \t]*(.*?)[ \t]*$")
_LITERAL = re.compile(r'^"([^"\\$%]*)"(?:[ \t]*(?:#.*|//.*))?$')
_STRING_LIST_ITEM = re.compile(r'"([^"\\$%]*)"')


def _depths(text: str) -> list[int]:
    """depths[i] = profondeur d'accolades AVANT le caractère i (chaînes, commentaires, heredocs ignorés)."""
    n = len(text)
    depths = [0] * (n + 1)
    depth = 0
    i = 0
    while i < n:
        depths[i] = depth
        c = text[i]
        if text.startswith(("#", "//"), i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i + 1, j):
                depths[k] = depth
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1:
                raise HCLError("commentaire /* non fermé")
            for k in range(i + 1, j + 2):
                depths[k] = depth
            i = j + 2
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n":
                    raise HCLError("chaîne non fermée")
                j += 1
            if j >= n:
                raise HCLError("chaîne non fermée")
            for k in range(i + 1, j + 1):
                depths[k] = depth
            i = j + 1
            continue
        m = _HEREDOC.match(text, i)
        if m:
            terminator = re.compile(rf"^[ \t]*{re.escape(m.group(1))}[ \t]*$", re.M)
            eol = text.find("\n", m.end())
            t = terminator.search(text, eol + 1) if eol != -1 else None
            if t is None:
                raise HCLError("heredoc non terminé")
            for k in range(i + 1, t.end()):
                depths[k] = depth
            i = t.end()
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                raise HCLError("accolade fermante en trop")
        i += 1
    depths[n] = depth
    if depth != 0:
        raise HCLError("accolades déséquilibrées")
    return depths


def find_resource_blocks(text: str) -> list[ResourceBlock]:
    depths = _depths(text)
    blocks: list[ResourceBlock] = []
    for i, c in enumerate(text):
        if c != "{" or depths[i] != 0:
            continue
        header = _HEADER.search(text[max(0, i - 400) : i])
        if header is None:
            continue
        end = i + 1
        while end < len(text) and not (text[end] == "}" and depths[end] == 1):
            end += 1
        start = max(0, i - 400) + header.start()
        start += len(text[start:i]) - len(text[start:i].lstrip("\n"))
        blocks.append(ResourceBlock(header.group(1), header.group(2), start, i + 1, end))
    return blocks


@dataclass(frozen=True)
class _Attribute:
    name: str
    raw: str
    line_start: int
    line_end: int  # fin du CONTENU de la ligne (avant un éventuel \r et le \n)
    indent: str
    eol: str  # fin de ligne d'origine, réutilisée à l'insertion


def _attributes(text: str, block: ResourceBlock) -> list[_Attribute]:
    """Attributs de premier niveau du bloc (pas ceux des sous-blocs), un par ligne."""
    depths = _depths(text)
    found: list[_Attribute] = []
    pos = block.body_start
    while pos < block.end:
        eol = text.find("\n", pos)
        eol = block.end if eol == -1 or eol > block.end else eol
        raw_line = text[pos:eol]
        line = raw_line.rstrip("\r")  # fichiers CRLF
        first = len(line) - len(line.lstrip())
        if line.strip() and depths[min(pos + first, len(text))] == 1:
            m = _ATTRIBUTE.match(line)
            if m and not line.lstrip().startswith(("#", "//")):
                eol_chars = "\r\n" if raw_line.endswith("\r") else "\n"
                found.append(
                    _Attribute(
                        m.group(1), m.group(2), pos, pos + len(line), line[:first], eol_chars
                    )
                )
        pos = eol + 1
    return found


def _literal(raw: str) -> str | None:
    m = _LITERAL.match(raw)
    return m.group(1) if m else None


_LIST_SHAPE = re.compile(r'^\[\s*(?:"[^"\\$%]*"\s*(?:,\s*"[^"\\$%]*"\s*)*,?\s*)?\]$', re.S)


def _literal_string_list(raw: str) -> list[str] | None:
    """Liste de littéraux `["a", "b"]` uniquement : toute interpolation/variable -> None."""
    if not _LIST_SHAPE.match(raw.strip()):
        return None
    return _STRING_LIST_ITEM.findall(raw)


def locate_bucket(text: str, bucket: str, resource_types: frozenset[str]) -> list[ResourceBlock]:
    """Blocs `resource` de ces types dont l'attribut `bucket` est le littéral `bucket`."""
    return [
        block
        for block in find_resource_blocks(text)
        if block.type in resource_types
        and any(a.name == "bucket" and _literal(a.raw) == bucket for a in _attributes(text, block))
    ]


def make_bucket_private(text: str, block: ResourceBlock) -> TerraformEdit:
    """Force `acl = "private"` dans le bloc. Lève AlreadyPrivateError si le code est déjà conforme (l'écart
    est alors côté infrastructure réelle : un `terraform apply`, pas une PR), NonLiteralValueError si `acl`
    n'est pas un littéral (variable...), sans rien deviner."""
    attrs = _attributes(text, block)
    acl = next((a for a in attrs if a.name == "acl"), None)
    if acl is not None:
        current = _literal(acl.raw)
        if current is None:
            raise NonLiteralValueError(f"acl = {acl.raw}")
        if current == "private":
            raise AlreadyPrivateError(block.name)
        replaced = f'{acl.indent}acl = "private"'
        after = text[: acl.line_start] + replaced + text[acl.line_end :]
        return TerraformEdit(text, after, block)
    anchor = next(a for a in attrs if a.name == "bucket")
    inserted = f'{anchor.eol}{anchor.indent}acl = "private"'
    after = text[: anchor.line_end] + inserted + text[anchor.line_end :]
    return TerraformEdit(text, after, block)


# ── P2.10 bis (DEC-004) : NET-SSH-OPEN-001 ───────────────────────────────────────────────


def locate_security_group_rule(
    text: str, rule_name: str, resource_types: frozenset[str]
) -> list[ResourceBlock]:
    """Blocs `resource` de ces types dont le NOM Terraform (2e chaîne de l'en-tête) est
    `rule_name` — à la différence du bucket, une règle réseau se retrouve par son nom de
    ressource, elle n'a pas d'attribut `bucket` qui joue ce rôle."""
    return [
        b for b in find_resource_blocks(text) if b.type in resource_types and b.name == rule_name
    ]


def close_open_cidr(text: str, block: ResourceBlock) -> TerraformEdit:
    """Retire `0.0.0.0/0` de `cidr_blocks`. Lève AlreadyClosedError si absent (dérive infra, pas
    un correctif de code), NonLiteralValueError si `cidr_blocks` n'est pas une liste de littéraux."""
    attrs = _attributes(text, block)
    cidr = next((a for a in attrs if a.name == "cidr_blocks"), None)
    if cidr is None:
        raise NonLiteralValueError("cidr_blocks absent")
    values = _literal_string_list(cidr.raw)
    if values is None:
        raise NonLiteralValueError(f"cidr_blocks = {cidr.raw}")
    if "0.0.0.0/0" not in values:
        raise AlreadyClosedError(block.name)
    remaining = [v for v in values if v != "0.0.0.0/0"]
    rendered = "[" + ", ".join(f'"{v}"' for v in remaining) + "]"
    replaced = f"{cidr.indent}cidr_blocks = {rendered}"
    after = text[: cidr.line_start] + replaced + text[cidr.line_end :]
    return TerraformEdit(text, after, block)
