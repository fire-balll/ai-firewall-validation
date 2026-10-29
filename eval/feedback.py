#!/usr/bin/env python3
"""배치 결과로 LLM 생성 후보의 피드백 JSON 을 만든다. 재생성(-r<라운드+1>)의 입력이다. (담당: 강윤서)

형식은 #21 에서 정한 초안을 따른다. 생성 후보(manifest 에 meta 가 있는 실행)만 다룬다.
  stage validation  검증 반려 (ok=false): validation.errors
  stage approval    고위험이라 적용하지 않음: validation.reasons (risk=high 를 만든 이유만, anomalies 는 넣지 않음)
  stage deploy      프로브 실패로 롤백: failed_probes (실패한 프로브만, 통과한 프로브는 넣지 않음)
applied(전부 통과)와 aborted(실행 실패)는 피드백을 만들지 않는다. 같은 후보를 여러 번 돌렸으면
aborted 가 아닌 가장 앞 rep 하나만 쓴다(반복마다 다른 실패가 섞이지 않게).

failed_probes 는 deploy.json 의 프로브 결과(id, kind, expect, observed)에 시나리오의 프로브 정의
(from, to, proto, port)와 출발지 IP(lab/topology.env)를 붙여 만든다. 도구(nc·nmap 등)는 넣지 않는다.
observed 의 allow 는 "방화벽이 통과시켰다"는 뜻이다(서버가 듣지 않는 포트의 Connection refused 포함).

아래 경우는 피드백을 하나도 쓰지 않고 종료 코드 1 로 끝낸다 (AGENTS.md 핵심 원칙):
  manifest 가 끝나지 않음(finished 없음), 커밋 안 된 변경으로 돌린 배치(--allow-dirty 없이),
  실행 산출물(validation.json, deploy.json) 없음, 롤백인데 실패한 프로브가 없음,
  실패한 프로브 id 가 시나리오에 없음, 이미 있는 피드백 파일(--overwrite 없이)

출력: {"written": [...], "skipped": [{"candidate", "rep", "status"}...]}
사용: feedback.py eval/results/batch-20261030-090000.json [--out-dir generated] [--dry-run]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.ir import ROOT, load_json  # noqa: E402
from common.topology import hosts  # noqa: E402

GENERATED = ROOT / "generated"
SCENARIOS = ROOT / "scenarios"
STAGES = {"rejected_validation": "validation", "rejected_approval": "approval", "rolled_back": "deploy"}


class FeedbackError(Exception):
    """피드백을 만들 근거가 부족하다. 결과를 꾸미지 않고 멈춘다."""


def _read(path, what):
    if not path.exists():
        raise FeedbackError(f"{what} 없음: {path}")
    return load_json(path)


def failed_probes(run, out, host_ips):
    deploy = _read(out / "deploy.json", "deploy.json")
    results = (deploy.get("probe") or {}).get("results") or []
    failed = [r for r in results if not r["pass"]]
    if not failed:
        raise FeedbackError(f"{run['candidate']} r{run['rep']}: 롤백인데 실패한 프로브가 없음 ({out})")
    probes = {p["id"]: p for p in _read(SCENARIOS / f"{run['scenario']}.json", "시나리오")["probes"]}
    out_probes = []
    for r in failed:
        p = probes.get(r["id"])
        if p is None:
            raise FeedbackError(f"{run['candidate']}: 실패한 프로브 {r['id']} 가 시나리오 {run['scenario']} 에 없음")
        item = {"id": r["id"], "kind": r["kind"], "from": p["from"], "from_ip": host_ips[p["from"]],
                "to": p["to"], "proto": p["proto"]}
        if "port" in p:
            item["port"] = p["port"]
        item.update(expect=r["expect"], observed=r["observed"])
        out_probes.append(item)
    return out_probes


def build(manifest, batch_id, host_ips):
    """manifest 에서 (후보 이름, 피드백) 목록과 건너뛴 실행 목록을 만든다."""
    chosen, skipped = {}, []
    for run in sorted(manifest["runs"], key=lambda r: r["rep"]):
        if "meta" not in run:
            continue  # gold·오류 주입은 재생성하지 않는다
        if run["status"] == "aborted" or run["candidate"] in chosen:
            skipped.append({"candidate": run["candidate"], "rep": run["rep"], "status": run["status"]})
            continue
        chosen[run["candidate"]] = run

    feedback = []
    for name, run in chosen.items():
        stage = STAGES.get(run["status"])
        if stage is None:  # applied: 모든 프로브 통과
            skipped.append({"candidate": name, "rep": run["rep"], "status": run["status"]})
            continue
        out = ROOT / run["out"]
        v = _read(out / "validation.json", "validation.json")
        fb = {
            "scenario": run["scenario"], "candidate": name, "round": run["meta"].get("round", 1),
            "source": {"batch_id": batch_id, "rep": run["rep"], "commit": manifest["commit"]},
            "stage": stage,
            "validation": {"ok": v["ok"], "risk": v["risk"], "errors": v["errors"], "reasons": v["reasons"]},
            "failed_probes": failed_probes(run, out, host_ips) if stage == "deploy" else [],
        }
        feedback.append((name, fb))
    return feedback, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", help="eval/results/batch-<id>.json")
    ap.add_argument("--out-dir", default=str(GENERATED), help="피드백 파일을 쓸 곳 (기본 generated/)")
    ap.add_argument("--overwrite", action="store_true", help="이미 있는 피드백 파일을 덮어쓴다")
    ap.add_argument("--allow-dirty", action="store_true", help="커밋 안 된 변경으로 돌린 배치도 쓴다 (실험용 아님)")
    ap.add_argument("--dry-run", action="store_true", help="파일을 쓰지 않고 결과만 출력한다")
    args = ap.parse_args()

    path = Path(args.manifest)
    manifest = load_json(path)
    try:
        if not manifest.get("finished"):
            raise FeedbackError(f"끝나지 않은 배치 (finished 없음): {path}")
        if manifest.get("dirty") and not args.allow_dirty:
            raise FeedbackError(f"커밋 안 된 변경으로 돌린 배치: {path} (--allow-dirty 로만 허용)")
        batch_id = path.stem.removeprefix("batch-")
        feedback, skipped = build(manifest, batch_id, hosts())
        out_dir = Path(args.out_dir)
        targets = [(out_dir / f"{name}.feedback.json", fb) for name, fb in feedback]
        existing = [str(t) for t, _ in targets if t.exists()]
        if existing and not args.overwrite:
            raise FeedbackError(f"이미 있는 피드백 파일: {', '.join(existing)} (--overwrite 로만 덮어씀)")
    except FeedbackError as e:
        sys.exit(f"피드백 생성 중단: {e}")

    # 모두 확인한 뒤에만 쓴다. 일부만 쓰고 멈추지 않게
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        for target, fb in targets:
            target.write_text(json.dumps(fb, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json.dump({"written": [str(t) for t, _ in targets], "skipped": skipped, "dry_run": args.dry_run},
              sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
