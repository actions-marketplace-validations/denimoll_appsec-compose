"""Terraform and Kubernetes findings merge per resource, Dockerfile ones per file."""
from baseline import _Source, assign
from dedup import merge
from iacunits import Units
from normalize import Finding

TF = '''resource "aws_s3_bucket" "data" {
  bucket = "data"
  acl    = "private"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  tags = { env = "${var.env}" }
}
'''

K8S = '''apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx
---
apiVersion: v1
kind: Pod
metadata:
  name: debug
spec:
  containers:
    - name: debug
      image: busybox
'''


def _f(tool, rule, line, file="main.tf", end_line=None):
    return Finding(tool=tool, category="iac", rule_id=rule, severity="medium",
                   message="m", file=file, line=line, end_line=end_line)


def test_units_are_named_by_the_resource_itself(tmp_path):
    (tmp_path / "main.tf").write_text(TF)
    (tmp_path / "k.yaml").write_text(K8S)
    units = Units(_Source(str(tmp_path)))
    assert units.label("main.tf", 2) == 'resource "aws_s3_bucket" "data"'
    assert units.label("main.tf", 8) == 'resource "aws_s3_bucket" "logs"'
    assert units.label("main.tf", 5) is None                 # between resources
    assert units.label("k.yaml", 11) == "Deployment/shop/web"
    assert units.label("k.yaml", 20) == "Pod/debug"


def test_two_buckets_stay_two_findings_three_engines_each_one(tmp_path):
    (tmp_path / "main.tf").write_text(TF)
    units = Units(_Source(str(tmp_path)))
    findings = [_f("checkov", "CKV_AWS_21", 1, end_line=4), _f("trivy", "AWS-0090", 2),
                _f("kics", "568a4d22-3517-44a6-a7ad-6a7eed88722c", 3),
                _f("checkov", "CKV_AWS_21", 6, end_line=9), _f("trivy", "AWS-0090", 7)]
    merged, stats = merge(findings, units=units)
    assert stats.unique == 2
    assert sorted(len(f.tools) for f in merged) == [2, 3]
    # Without the code to place them, nothing merges on a guess.
    assert merge(findings)[1].unique == 5


def test_a_resource_finding_keeps_its_fingerprint_when_lines_move(tmp_path):
    (tmp_path / "main.tf").write_text(TF)
    first = _f("trivy", "AWS-0090", 7)
    assign([first], str(tmp_path))
    (tmp_path / "main.tf").write_text("# header\n\n" + TF)
    moved = _f("trivy", "AWS-0090", 9)
    assign([moved], str(tmp_path))
    assert first.fingerprint == moved.fingerprint


def test_kics_joins_the_dockerfile_and_workflow_classes():
    merged, _ = merge([_f("trivy", "DS-0001", 1, file="Dockerfile"),
                       _f("kics", "f45ea400-6bbe-4501-9fc7-1c3d75c32067", 2, file="Dockerfile")])
    assert len(merged) == 1 and merged[0].tools == ["kics", "trivy"]
