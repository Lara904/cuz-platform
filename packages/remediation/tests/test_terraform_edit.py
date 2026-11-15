# packages/remediation/tests/test_terraform_edit.py
import pytest

from packages.remediation.terraform_edit import (
    AlreadyClosedError,
    AlreadyNotPermanentError,
    AlreadyPrivateError,
    HCLError,
    NonLiteralValueError,
    close_open_cidr,
    find_resource_blocks,
    locate_bucket,
    locate_role,
    locate_security_group_rule,
    make_bucket_private,
    revoke_permanent_admin,
)

TYPES = frozenset({"minio_s3_bucket", "aws_s3_bucket"})

PUBLIC = """# Buckets AcmeCorp
resource "minio_s3_bucket" "public" {
  bucket = "acmecorp-public"
  acl    = "public"

  lifecycle {
    prevent_destroy = true
  }
}

resource "minio_s3_bucket" "data" {
  bucket = "acmecorp-data"
  acl    = "private"
}
"""


def _edit(text: str, bucket: str = "acmecorp-public"):
    (block,) = locate_bucket(text, bucket, TYPES)
    return make_bucket_private(text, block)


def test_public_acl_is_replaced_and_nothing_else_changes():
    edit = _edit(PUBLIC)
    assert 'acl = "private"' in edit.after
    changed = [
        (a, b) for a, b in zip(PUBLIC.splitlines(), edit.after.splitlines(), strict=True) if a != b
    ]
    assert changed == [('  acl    = "public"', '  acl = "private"')]


def test_missing_acl_is_inserted_after_the_bucket_line_with_same_indent():
    text = (
        'resource "aws_s3_bucket" "x" {\n    bucket = "b1"\n    tags = {\n      a = "b"\n    }\n}\n'
    )
    edit = _edit(text, "b1")
    assert edit.after.splitlines()[:3] == [
        'resource "aws_s3_bucket" "x" {',
        '    bucket = "b1"',
        '    acl = "private"',
    ]
    assert edit.after.endswith(text.split("tags")[1])  # le reste est intact


def test_already_private_in_code_is_refused_it_is_a_drift_not_a_code_fix():
    with pytest.raises(AlreadyPrivateError):
        _edit(PUBLIC, "acmecorp-data")


def test_non_literal_acl_is_refused_not_guessed():
    text = 'resource "aws_s3_bucket" "x" {\n  bucket = "b1"\n  acl = var.acl\n}\n'
    with pytest.raises(NonLiteralValueError):
        _edit(text, "b1")


def test_nested_block_attributes_are_not_mistaken_for_top_level_ones():
    text = (
        'resource "aws_s3_bucket" "x" {\n  bucket = "b1"\n'
        '  website {\n    acl = "public-read"\n    bucket = "decoy"\n  }\n}\n'
    )
    assert locate_bucket(text, "decoy", TYPES) == []
    edit = _edit(text, "b1")  # pas d'acl de premier niveau : insertion, le sous-bloc est intact
    assert 'acl = "public-read"' in edit.after and edit.after.count('acl = "private"') == 1


def test_resource_in_comment_or_string_is_ignored():
    text = (
        '# resource "aws_s3_bucket" "ghost" {\n#   bucket = "b1"\n# }\n'
        '/* resource "aws_s3_bucket" "ghost2" {\n  bucket = "b1"\n} */\n'
        'locals {\n  doc = "resource \\"aws_s3_bucket\\" \\"g\\" { bucket = \\"b1\\" }"\n}\n'
    )
    assert locate_bucket(text, "b1", TYPES) == []


def test_unknown_resource_type_is_not_matched():
    text = 'resource "aws_instance" "x" {\n  bucket = "b1"\n}\n'
    assert locate_bucket(text, "b1", TYPES) == []


def test_unknown_bucket_is_not_found():
    assert locate_bucket(PUBLIC, "inconnu", TYPES) == []


def test_two_blocks_for_the_same_bucket_are_both_reported_for_the_caller_to_refuse():
    text = PUBLIC + PUBLIC
    assert len(locate_bucket(text, "acmecorp-public", TYPES)) == 2


def test_bucket_from_variable_is_not_matched():
    text = 'resource "aws_s3_bucket" "x" {\n  bucket = var.name\n}\n'
    assert locate_bucket(text, "anything", TYPES) == []


def test_interpolated_bucket_name_is_not_treated_as_a_literal():
    text = 'resource "aws_s3_bucket" "x" {\n  bucket = "acmecorp-${var.env}"\n}\n'
    assert locate_bucket(text, "acmecorp-${var.env}", TYPES) == []


def test_heredoc_with_braces_does_not_break_parsing():
    text = 'resource "aws_s3_bucket" "x" {\n  bucket = "b1"\n  policy = <<EOT\n{ "a": { "b": 1 }\nEOT\n}\n'
    assert [b.name for b in find_resource_blocks(text)] == ["x"]
    assert 'acl = "private"' in _edit(text, "b1").after


@pytest.mark.parametrize(
    "text",
    ['resource "aws_s3_bucket" "x" {\n  bucket = "b1"\n', 'locals { a = "oups }\n', "}\n"],
)
def test_unparseable_files_raise_instead_of_being_guessed(text):
    with pytest.raises(HCLError):
        find_resource_blocks(text)


def test_diff_is_a_unified_diff_with_the_file_path():
    diff = _edit(PUBLIC).diff("storage/buckets.tf")
    assert diff.startswith("--- a/storage/buckets.tf\n+++ b/storage/buckets.tf\n")
    assert '-  acl    = "public"' in diff and '+  acl = "private"' in diff


def test_crlf_files_are_matched_and_keep_their_line_endings():
    text = PUBLIC.replace("\n", "\r\n")
    edit = _edit(text)
    assert edit.after.count("\r\n") == text.count("\r\n")
    assert "\n" not in edit.after.replace("\r\n", "")  # aucune fin de ligne mélangée


def test_crlf_insertion_uses_crlf_too():
    text = 'resource "aws_s3_bucket" "x" {\r\n  bucket = "b1"\r\n}\r\n'
    after = _edit(text, "b1").after
    assert (
        after == 'resource "aws_s3_bucket" "x" {\r\n  bucket = "b1"\r\n  acl = "private"\r\n}\r\n'
    )


# ── P2.10 bis (DEC-004) : NET-SSH-OPEN-001, close_open_cidr ─────────────────────────────

NSG_TYPES = frozenset({"aws_security_group_rule"})

SSH_OPEN = """resource "aws_security_group_rule" "ssh_open_world" {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
"""


def _close(text: str, name: str = "ssh_open_world"):
    (block,) = locate_security_group_rule(text, name, NSG_TYPES)
    return close_open_cidr(text, block)


def test_located_by_terraform_resource_name_not_an_attribute():
    assert len(locate_security_group_rule(SSH_OPEN, "ssh_open_world", NSG_TYPES)) == 1
    assert locate_security_group_rule(SSH_OPEN, "autre", NSG_TYPES) == []


def test_open_cidr_is_removed_and_nothing_else_changes():
    edit = _close(SSH_OPEN)
    assert 'cidr_blocks = ["0.0.0.0/0"]' not in edit.after
    assert "cidr_blocks = []" in edit.after
    changed = [
        (a, b)
        for a, b in zip(SSH_OPEN.splitlines(), edit.after.splitlines(), strict=True)
        if a != b
    ]
    assert changed == [('  cidr_blocks = ["0.0.0.0/0"]', "  cidr_blocks = []")]


def test_open_cidr_among_others_only_removes_that_entry():
    text = SSH_OPEN.replace('["0.0.0.0/0"]', '["10.0.0.0/8", "0.0.0.0/0"]')
    edit = _close(text)
    assert 'cidr_blocks = ["10.0.0.0/8"]' in edit.after


def test_already_closed_cidr_is_refused_it_is_infra_drift():
    text = SSH_OPEN.replace('["0.0.0.0/0"]', '["10.0.0.0/8"]')
    with pytest.raises(AlreadyClosedError):
        _close(text)


def test_non_literal_cidr_list_is_refused_not_guessed():
    text = SSH_OPEN.replace('["0.0.0.0/0"]', "var.allowed_cidrs")
    with pytest.raises(NonLiteralValueError):
        _close(text)


def test_missing_cidr_blocks_attribute_is_refused():
    text = 'resource "aws_security_group_rule" "x" {\n  from_port = 22\n  to_port = 22\n}\n'
    (block,) = locate_security_group_rule(text, "x", NSG_TYPES)
    with pytest.raises(NonLiteralValueError):
        close_open_cidr(text, block)


# ── P2.10 bis (DEC-004) : CIS-011, revoke_permanent_admin ───────────────────────────────

ROLE_TYPES = frozenset({"aws_iam_role"})

ROLE_PERMANENT = """resource "aws_iam_role" "permanent_admin_role" {
  name      = "permanent-admin-role"
  is_admin  = true
  permanent = true
}
"""


def _revoke(text: str, name: str = "permanent-admin-role"):
    (block,) = locate_role(text, name, ROLE_TYPES)
    return revoke_permanent_admin(text, block)


def test_role_located_by_name_attribute_not_resource_name():
    assert len(locate_role(ROLE_PERMANENT, "permanent-admin-role", ROLE_TYPES)) == 1
    assert locate_role(ROLE_PERMANENT, "permanent_admin_role", ROLE_TYPES) == []
    assert locate_role(ROLE_PERMANENT, "autre", ROLE_TYPES) == []


def test_permanent_is_flipped_to_false_and_nothing_else_changes():
    edit = _revoke(ROLE_PERMANENT)
    assert "permanent = false" in edit.after
    changed = [
        (a, b)
        for a, b in zip(ROLE_PERMANENT.splitlines(), edit.after.splitlines(), strict=True)
        if a != b
    ]
    assert changed == [("  permanent = true", "  permanent = false")]


def test_already_not_permanent_is_refused_it_is_infra_drift():
    text = ROLE_PERMANENT.replace("permanent = true", "permanent = false")
    with pytest.raises(AlreadyNotPermanentError):
        _revoke(text)


def test_non_literal_permanent_is_refused_not_guessed():
    text = ROLE_PERMANENT.replace("permanent = true", "permanent = var.is_permanent")
    with pytest.raises(NonLiteralValueError):
        _revoke(text)


def test_missing_permanent_attribute_is_refused():
    text = 'resource "aws_iam_role" "x" {\n  name = "x-role"\n}\n'
    (block,) = locate_role(text, "x-role", ROLE_TYPES)
    with pytest.raises(NonLiteralValueError):
        revoke_permanent_admin(text, block)
