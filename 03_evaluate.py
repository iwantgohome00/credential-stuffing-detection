# ① 기본 설정: 평가할 파일 선택 (기본값 v1, 4단계에서는 v2 파일을 넣어 재사용)
import csv
import sys
from collections import defaultdict

INPUT = sys.argv[1] if len(sys.argv) > 1 else "detections_v1.csv"

with open(INPUT, encoding="utf-8") as f:
    rows = list(csv.DictReader(f))


# ② 혼동 행렬 계산: 정답(label)과 탐지 결과(detected) 비교
def confusion(pairs):
    tp = sum(actual and pred for actual, pred in pairs)          # 공격을 공격으로 (정탐)
    fn = sum(actual and not pred for actual, pred in pairs)      # 공격을 놓침 (미탐)
    fp = sum(not actual and pred for actual, pred in pairs)      # 정상을 공격으로 (오탐)
    tn = sum(not actual and not pred for actual, pred in pairs)  # 정상을 정상으로
    return tp, fn, fp, tn


def report(title, pairs, unit):
    tp, fn, fp, tn = confusion(pairs)
    recall = tp / (tp + fn) if tp + fn else 0       # 탐지율: 실제 공격 중 잡은 비율
    precision = tp / (tp + fp) if tp + fp else 0    # 정밀도: 탐지한 것 중 진짜 공격 비율
    fpr = fp / (fp + tn) if fp + tn else 0          # 오탐률: 정상 중 공격으로 잘못 본 비율
    print(f"[{title}]")
    print(f"               탐지함   탐지 안 함")
    print(f"  실제 공격  {tp:>7}  {fn:>9}")
    print(f"  실제 정상  {fp:>7}  {tn:>9}")
    print(f"  탐지율(Recall)  : {recall:6.1%}  ({tp}/{tp + fn}{unit})")
    print(f"  정밀도(Precision): {precision:6.1%}  ({tp}/{tp + fp}{unit})")
    print(f"  오탐률(FPR)     : {fpr:6.1%}  ({fp}/{fp + tn}{unit})\n")


# ③ 로그 단위 평가: 로그 한 줄 한 줄이 맞게 분류됐는가
log_pairs = [(r["label"] == "attack", r["detected"] == "1") for r in rows]
report("로그 단위", log_pairs, "건")

# ④ IP 단위 평가: 실제 차단은 IP 단위로 하므로 더 중요
ip_actual, ip_pred, ip_scen = defaultdict(bool), defaultdict(bool), {}
for r in rows:
    ip = r["src_ip"]
    ip_actual[ip] |= r["label"] == "attack"
    ip_pred[ip] |= r["detected"] == "1"
    ip_scen[ip] = r["scenario"]
report("IP 단위", [(ip_actual[ip], ip_pred[ip]) for ip in ip_actual], "개")

# ⑤ 시나리오별 탐지 현황: 어떤 상황을 잘 잡고 어떤 상황에서 틀렸는가
print("[시나리오별 IP 탐지 현황]")
scen_total, scen_hit = defaultdict(int), defaultdict(int)
for ip, scen in ip_scen.items():
    scen_total[scen] += 1
    scen_hit[scen] += ip_pred[ip]
for scen in ["burst", "distributed", "stealth", "low_slow", "office_nat", "forgetful", "normal"]:
    kind = "공격" if scen in ("burst", "distributed", "stealth", "low_slow") else "정상"
    print(f"  {scen:<12}({kind}) : {scen_hit[scen]:>3} / {scen_total[scen]:>3} IP 탐지")

# ⑥ 계정 탈취 탐지: 공격이 성공한 로그인을 잡았는가 (실제 피해와 직결)
takeovers = [r for r in rows if r["label"] == "attack" and r["result"] == "SUCCESS"]
caught = sum(r["detected"] == "1" for r in takeovers)
print(f"\n[계정 탈취(공격 성공 로그인) 탐지] {caught} / {len(takeovers)}건")
for r in takeovers:
    if r["detected"] != "1":
        print(f"  놓침: {r['timestamp']}  {r['user_id']:<9} {r['src_ip']:<16} ({r['scenario']})")

# ⑦ 놓친 공격 IP와 오탐 IP 목록: 4단계 개선의 근거
print("\n[놓친 공격 IP]")
for ip in ip_actual:
    if ip_actual[ip] and not ip_pred[ip]:
        ev = [r for r in rows if r["src_ip"] == ip]
        seq = "".join("O" if r["result"] == "SUCCESS" else "X" for r in ev)
        print(f"  {ip:<16} 시도 {len(ev)}건, 결과 순서 {seq}")

print("\n[오탐 IP]")
for ip in ip_actual:
    if not ip_actual[ip] and ip_pred[ip]:
        ev = [r for r in rows if r["src_ip"] == ip]
        print(f"  {ip:<16} {ip_scen[ip]:<11} 시도 {len(ev)}건, 규칙 {ev[0]['rules']}")
