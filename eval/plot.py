#!/usr/bin/env python3
"""집계 결과로 발표용 그래프(SVG)를 그린다. (담당: 강윤서)

입력은 이미 검증을 거친 집계 결과다. 여기서 CSV·manifest 를 다시 읽거나 값을 채우지 않는다.
  summary.py 출력 JSON      status.svg   배치·후보 종류별 실행 상태 비율 (100% 누적 막대)
                            detect.svg   오류 주입 후보의 시나리오별 평균 감지 시간
                            mttr.svg     오류 주입 후보의 시나리오별 평균 복구 시간
  detection.py 출력 JSON    detection.svg  오류 유형별 정적·동적·놓침 수 (--detection 을 줄 때만)
감지 시간과 복구 시간은 단위 크기가 달라 한 그림에 축 두 개로 넣지 않고 따로 그린다.
표로 볼 값은 summary.py --csv-out 이 같은 숫자를 낸다.

외부 패키지 없이 표준 라이브러리로 SVG 를 쓴다 (requirements.txt 에 추가하지 않기 위해).
입력에 필요한 키가 없으면 그림을 내지 않고 종료 코드 1.
사용: summary.py eval/results/batch-*.json > out/summary.json
      plot.py out/summary.json [--detection out/detection.json] [--out-dir out/plots]
"""

import argparse
import json
import sys
from html import escape
from pathlib import Path

# 범주 색은 고정 순서로 쓴다 (dataviz 검증: 인접 쌍 CVD ΔE >= 9.1, 일반 시각 >= 19.6).
# 3·4·5번은 바탕 대비 3:1 미만이라 범례와 막대 끝 숫자를 항상 함께 단다.
SERIES = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4")
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
FONT = "Pretendard, 'Apple SD Gothic Neo', 'Noto Sans KR', sans-serif"

STATUSES = (("applied", "적용 유지"), ("rolled_back", "롤백"), ("rejected_approval", "승인 거부"),
            ("rejected_validation", "검증 반려"), ("aborted", "실행 실패"))
KINDS = {"gold": "정답", "mutation": "오류 주입", "generated": "AI 후보"}
OUTCOMES = (("static", "정적 검증이 잡음"), ("dynamic", "동적 검증만 잡음"), ("missed", "놓침"))

W, LEFT, RIGHT, BAR, ROW = 720, 150, 70, 20, 36


class PlotError(Exception):
    """그릴 근거가 부족하다. 그림을 꾸미지 않고 멈춘다."""


def _need(d, key, where):
    if key not in d:
        raise PlotError(f"{where} 에 {key} 없음")
    return d[key]


def _svg(height, title, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" viewBox="0 0 {W} {height}" '
            f'font-family="{FONT}" role="img" aria-label="{escape(title)}">\n'
            f'<rect width="{W}" height="{height}" fill="{SURFACE}"/>\n'
            f'<text x="24" y="32" font-size="18" font-weight="600" fill="{INK}">{escape(title)}</text>\n'
            + "\n".join(body) + "\n</svg>\n")


def _text_w(s, size=13):
    """글자 폭 근사: 한글 등은 글자 크기만큼, 그 외(숫자·영문)는 0.62배."""
    return sum(size if ord(c) > 127 else size * 0.62 for c in s)


def _legend(items, y, x=LEFT):
    out = []
    for color, name in items:
        out.append(f'<rect x="{x}" y="{y - 10}" width="12" height="12" rx="2" fill="{color}"/>'
                   f'<text x="{x + 18}" y="{y}" font-size="13" fill="{INK2}">{escape(name)}</text>')
        x += 30 + 14 * len(name)
    return out


def _bar(x, y, w, color, tip, round_end):
    """막대 한 칸. 끝(오른쪽)만 4px 둥글게, 기준선 쪽은 각지게."""
    if w <= 0:
        return ""
    r = min(4, w) if round_end else 0
    path = (f"M{x},{y} H{x + w - r} Q{x + w},{y} {x + w},{y + r} V{y + BAR - r} "
            f"Q{x + w},{y + BAR} {x + w - r},{y + BAR} H{x} Z")
    return f'<path d="{path}" fill="{color}"><title>{escape(tip)}</title></path>'


def _stacked(rows, series, title):
    """rows: [(라벨, {키: 수})]. 줄마다 100% 누적 막대, 칸 사이 2px 바탕 틈.
    왼쪽 여백은 가장 긴 행 이름에 맞춘다 (배치 ID 가 붙은 이름이 잘리지 않게)."""
    left = max(LEFT, round(24 + max(_text_w(label) for label, _ in rows) + 12))
    plot_w = W - left - RIGHT
    top = 84
    body = _legend([(SERIES[i], name) for i, (_, name) in enumerate(series)], 62, left)
    for i, (label, counts) in enumerate(rows):
        y = top + i * ROW
        total = sum(counts.get(k, 0) for k, _ in series)
        if not total:
            raise PlotError(f"{label}: 실행 수 0")
        body.append(f'<text x="{left - 12}" y="{y + 15}" font-size="13" fill="{INK}" text-anchor="end">'
                    f'{escape(label)}</text>')
        parts = [(k, name, counts.get(k, 0)) for k, name in series]
        last = max(j for j, (_, _, n) in enumerate(parts) if n)
        x = left
        for j, (_, name, n) in enumerate(parts):
            if not n:
                continue
            w = plot_w * n / total - (0 if j == last else 2)
            body.append(_bar(x, y, w, SERIES[j], f"{label} · {name} {n}회 ({n / total:.0%})", j == last))
            x += w + 2
        body.append(f'<text x="{left + plot_w + 8}" y="{y + 15}" font-size="13" fill="{INK2}">{total}회</text>')
    return _svg(top + len(rows) * ROW + 16, title, body)


def _bars(rows, unit, title):
    """rows: [(라벨, 값)]. 가로 막대, 끝에 값. 축은 0 부터."""
    plot_w = W - LEFT - RIGHT
    top = 60
    vmax = max(v for _, v in rows) or 1
    body = []
    for t in (0, 0.5, 1):
        x = LEFT + plot_w * t
        body.append(f'<line x1="{x}" y1="{top - 6}" x2="{x}" y2="{top + len(rows) * ROW}" stroke="{GRID}"/>'
                    f'<text x="{x}" y="{top + len(rows) * ROW + 16}" font-size="11" fill="{INK2}" '
                    f'text-anchor="middle">{vmax * t:.3g}{unit}</text>')
    for i, (label, v) in enumerate(rows):
        y = top + i * ROW
        w = plot_w * v / vmax
        body.append(f'<text x="{LEFT - 12}" y="{y + 15}" font-size="13" fill="{INK}" text-anchor="end">'
                    f'{escape(label)}</text>')
        body.append(_bar(LEFT, y, w, SERIES[0], f"{label} {v:.3g}{unit}", True))
        body.append(f'<text x="{LEFT + w + 6}" y="{y + 15}" font-size="12" fill="{INK2}">{v:.3g}{unit}</text>')
    return _svg(top + len(rows) * ROW + 28, title, body)


def status_chart(summary):
    rows = []
    for b in _need(summary, "batches", "summary"):
        for k, s in sorted(_need(b, "kinds", "batch").items(), key=lambda kv: list(KINDS).index(kv[0])):
            rows.append((k, b["batch_id"], _need(s, "status", k)))
    if not rows:
        raise PlotError("summary 에 배치 없음")
    kinds = [k for k, _, _ in rows]  # 같은 종류가 여러 배치에 있으면 배치 ID 를 붙여 구분한다
    rows = [(KINDS.get(k, k) + (f" {b}" if kinds.count(k) > 1 else ""), st) for k, b, st in rows]
    return _stacked(rows, STATUSES, "후보 종류별 실행 결과")


def timing_rows(summary, metric):
    """오류 주입 후보의 시나리오별 평균. 후보 평균을 실행 수(n)로 가중해 합친다."""
    acc = {}
    for g in _need(summary, "groups", "summary"):
        if g["kind"] != "mutation":
            continue
        m = _need(g, metric, g["candidate"])
        if m["n"]:
            s, n = acc.get(g["scenario"], (0.0, 0))
            acc[g["scenario"]] = (s + m["mean"] * m["n"], n + m["n"])
    if not acc:
        raise PlotError(f"오류 주입 실행 중 {metric} 값이 있는 것이 없음")
    return [(sc, s / n) for sc, (s, n) in sorted(acc.items())]


def detection_chart(detection):
    by_type = _need(detection, "by_type", "detection")
    rows = [(t, {"static": c["static"], "dynamic": c["dynamic"], "missed": c["missed"]})
            for t, c in sorted(by_type.items())]
    if not rows:
        raise PlotError("detection 에 오류 유형 없음")
    return _stacked(rows, OUTCOMES, f"오류 유형별 검증 결과 (배치 {detection.get('batch_id', '?')})")


def render(summary, detection=None):
    out = {"status.svg": status_chart(summary),
           "detect.svg": _bars(timing_rows(summary, "detect_s"), "초", "오류 주입: 시나리오별 평균 감지 시간"),
           "mttr.svg": _bars(timing_rows(summary, "mttr_s"), "초", "오류 주입: 시나리오별 평균 복구 시간")}
    if detection is not None:
        out["detection.svg"] = detection_chart(detection)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("summary", help="summary.py 출력 JSON")
    ap.add_argument("--detection", help="detection.py 출력 JSON")
    ap.add_argument("--out-dir", default="out/plots")
    args = ap.parse_args()
    try:
        summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
        detection = json.loads(Path(args.detection).read_text(encoding="utf-8")) if args.detection else None
        files = render(summary, detection)
    except (PlotError, FileNotFoundError, json.JSONDecodeError) as e:
        sys.exit(f"그래프 중단: {e}")
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, svg in files.items():
        (out / name).write_text(svg, encoding="utf-8")
        print(out / name)


if __name__ == "__main__":
    main()
