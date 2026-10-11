# ① 기본 설정
import csv
from collections import defaultdict
from datetime import datetime, timedelta

INPUT = "login_logs.csv"
OUTPUT = "detections_v1.csv"

# 탐지 기준값 (임계값)
WINDOW = timedelta(minutes=5)   # R1: 짧은 시간 기준
MAX_IN_WINDOW = 10              # R1: 5분 안에 10번 이상 시도하면 의심
MAX_ACCOUNTS = 20               # R2: 하루에 서로 다른 계정 20개 이상 시도하면 의심
MAX_CONSEC_FAIL = 5             # R3: 5번 연속 실패하면 의심
BOT_KEYWORDS = ["python-requests", "curl", "wget", "go-http-client"]  # R4: 자동화 도구 이름


# ② 로그 읽기 (label, scenario 칸은 정답이므로 탐지에 사용하지 않음)
def load_logs():
    with open(INPUT, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["ts"] = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
    return rows


# ③ IP별로 로그 묶기
def group_by_ip(rows):
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["src_ip"]].append(r)
    return by_ip


# ④ 탐지 규칙 4가지
def rule_velocity(events):
    """R1 속도: 5분 안에 시도 횟수가 기준 이상인가"""
    times = [e["ts"] for e in events]
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > WINDOW:
            start += 1
        if end - start + 1 >= MAX_IN_WINDOW:
            return True
    return False


def rule_many_accounts(events):
    """R2 계정 다양성: 한 IP가 서로 다른 계정을 너무 많이 시도했는가"""
    return len({e["user_id"] for e in events}) >= MAX_ACCOUNTS


def rule_consecutive_fail(events):
    """R3 연속 실패: 실패가 연속으로 기준 횟수 이상 이어졌는가"""
    streak = 0
    for e in events:
        streak = streak + 1 if e["result"] == "FAIL" else 0
        if streak >= MAX_CONSEC_FAIL:
            return True
    return False


def rule_bot_ua(events):
    """R4 봇 UA: 자동화 도구의 User-Agent를 썼는가"""
    return any(k in e["user_agent"].lower() for e in events for k in BOT_KEYWORDS)


RULES = {
    "R1_velocity": rule_velocity,
    "R2_many_accounts": rule_many_accounts,
    "R3_consecutive_fail": rule_consecutive_fail,
    "R4_bot_ua": rule_bot_ua,
}


# ⑤ IP마다 규칙 적용 → 하나라도 걸리면 탐지
def detect(by_ip):
    flagged = {}
    for ip, events in by_ip.items():
        hits = [name for name, rule in RULES.items() if rule(events)]
        if hits:
            flagged[ip] = hits
    return flagged


# ⑥ 실행, 결과 출력 및 저장
rows = load_logs()
by_ip = group_by_ip(rows)
flagged = detect(by_ip)

print(f"전체 IP 수: {len(by_ip)} / 탐지된 IP 수: {len(flagged)}\n")
print(f"{'IP':<17}{'시도':>5}{'계정수':>7}{'실패':>5}  걸린 규칙")
for ip, hits in sorted(flagged.items(), key=lambda x: -len(by_ip[x[0]])):
    ev = by_ip[ip]
    accounts = len({e["user_id"] for e in ev})
    fails = sum(e["result"] == "FAIL" for e in ev)
    print(f"{ip:<17}{len(ev):>5}{accounts:>7}{fails:>5}  {', '.join(hits)}")

print("\n규칙별 탐지 IP 수:")
for name in RULES:
    print(f"  {name}: {sum(name in h for h in flagged.values())}")

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    fields = [k for k in rows[0] if k != "ts"] + ["detected", "rules"]
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        hits = flagged.get(r["src_ip"], [])
        writer.writerow({**r, "detected": int(bool(hits)), "rules": "|".join(hits)})

print(f"\n탐지된 로그 수: {sum(len(by_ip[ip]) for ip in flagged)} / 전체 {len(rows)}")
print(f"저장 완료: {OUTPUT}")
