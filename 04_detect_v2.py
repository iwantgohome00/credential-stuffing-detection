# ① 기본 설정
import csv
from collections import defaultdict
from datetime import datetime, timedelta

INPUT = "login_logs.csv"
OUTPUT = "detections_v2.csv"

WINDOW = timedelta(minutes=5)
MAX_IN_WINDOW = 10
BOT_KEYWORDS = ["python-requests", "curl", "wget", "go-http-client"]
SCORE_THRESHOLD = 3          # 위험 점수가 3점 이상이면 탐지


# ② 로그 읽기와 IP별 묶기 (v1과 동일, label은 사용하지 않음)
def load_logs():
    with open(INPUT, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["ts"] = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
    return rows


def group_by_ip(rows):
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["src_ip"]].append(r)
    return by_ip


def has_burst(events):
    times = [e["ts"] for e in events]
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > WINDOW:
            start += 1
        if end - start + 1 >= MAX_IN_WINDOW:
            return True
    return False


# ③ IP별 특징 계산: "연속" 대신 "비율"을 사용해 성공이 섞여도 흔들리지 않게 함
def features(events):
    n = len(events)
    return {
        "attempts": n,
        "accounts": len({e["user_id"] for e in events}),
        "fail_rate": sum(e["result"] == "FAIL" for e in events) / n,
        "nosuch_count": sum(e["reason"] == "NO_SUCH_USER" for e in events),
        "nosuch_rate": sum(e["reason"] == "NO_SUCH_USER" for e in events) / n,
        "success_rate": sum(e["result"] == "SUCCESS" for e in events) / n,
        "burst": has_burst(events),
        "bot_ua": any(k in e["user_agent"].lower() for e in events for k in BOT_KEYWORDS),
    }


# ④ 위험 점수 계산: 신호 여러 개를 합산하고, 정상 패턴이면 감점
def score(f):
    if f["accounts"] == 1:
        return 0, ["EXCLUDE_single_account"]   # 계정 1개만 시도 → 크리덴셜 스터핑 아님

    s, reasons = 0, []
    if f["nosuch_count"] >= 2 and f["nosuch_rate"] >= 0.3:
        s += 3; reasons.append("S1_nosuch_user")       # 없는 계정 대입 = 유출 목록 사용 흔적
    if f["accounts"] >= 3 and f["fail_rate"] >= 0.5:
        s += 2; reasons.append("S2_multi_account_fail")  # 여러 계정에서 실패가 많음
    if f["burst"]:
        s += 2; reasons.append("S3_velocity")            # 사람이 낼 수 없는 속도
    if f["bot_ua"]:
        s += 3; reasons.append("S4_bot_ua")              # 자동화 도구
    if f["accounts"] >= 20:
        s += 1; reasons.append("S5_many_accounts")       # 계정 다양성
    if f["success_rate"] >= 0.8:
        s -= 3; reasons.append("D1_high_success")        # 대부분 성공 → 공용 IP 등 정상
    return s, reasons


# ⑤ 실행: 탐지 대상과 '단일 계정 반복 실패(관찰 대상)'를 분리
rows = load_logs()
by_ip = group_by_ip(rows)

result, watch = {}, []
for ip, events in by_ip.items():
    f = features(events)
    s, reasons = score(f)
    result[ip] = (s, reasons, f)
    if f["accounts"] == 1 and f["fail_rate"] == 1 and f["attempts"] >= 5:
        watch.append((ip, events[0]["user_id"], f["attempts"]))

flagged = {ip for ip, (s, _, _) in result.items() if s >= SCORE_THRESHOLD}

# ⑥ 출력: 탐지 IP, 점수 경계에 있던 IP, 관찰 대상
print(f"전체 IP 수: {len(by_ip)} / 탐지된 IP 수: {len(flagged)}\n")
print(f"{'IP':<17}{'점수':>4}{'시도':>5}{'계정':>5}{'실패율':>7}{'없는계정':>8}  신호")
for ip in sorted(result, key=lambda x: -result[x][0]):
    s, reasons, f = result[ip]
    if s >= 1 or "D1_high_success" in reasons:
        mark = "탐지" if ip in flagged else "통과"
        print(f"{ip:<17}{s:>4}{f['attempts']:>5}{f['accounts']:>5}{f['fail_rate']:>7.0%}"
              f"{f['nosuch_rate']:>8.0%}  [{mark}] {', '.join(reasons)}")

print("\n[관찰 대상: 단일 계정 반복 실패 → IP 차단 대신 계정 보호 조치]")
for ip, user, n in watch:
    print(f"  {ip:<16} {user} {n}회 연속 실패")

# ⑦ 저장: 03_evaluate.py로 그대로 평가할 수 있게 v1과 같은 형식
with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    fields = [k for k in rows[0] if k != "ts"] + ["detected", "rules", "score"]
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        s, reasons, _ = result[r["src_ip"]]
        writer.writerow({**r, "detected": int(r["src_ip"] in flagged),
                         "rules": "|".join(reasons), "score": s})

print(f"\n저장 완료: {OUTPUT}")
