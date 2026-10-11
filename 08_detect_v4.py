# ① 기본 설정: v3(IP 기준)에 ASN/서브넷 집계와 글로벌 베이스라인을 더해
#    low-and-slow(저속 분산) 공격을 잡는다.
import csv
from collections import defaultdict
from datetime import datetime, timedelta

INPUT = "login_logs_trend.csv"
OUTPUT = "detections_v4.csv"

WINDOW = timedelta(minutes=5)
MAX_IN_WINDOW = 10
BOT_KEYWORDS = ["python-requests", "curl", "wget", "go-http-client"]
HOSTING_HINT = ["selectel", "digitalocean", "contabo", "alexhost", "aws", "amazon"]
HOME_COUNTRY = "KR"
IP_THRESHOLD = 4


def load_logs():
    with open(INPUT, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["ts"] = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
        r["subnet"] = ".".join(r["src_ip"].split(".")[:3]) + ".0/24"   # /24 서브넷
    return rows


# ② [1층] IP 기준 탐지 (v3와 동일) — low-and-slow는 여기서 대부분 빠져나간다
def has_burst(events):
    times = sorted(e["ts"] for e in events)
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > WINDOW:
            start += 1
        if end - start + 1 >= MAX_IN_WINDOW:
            return True
    return False


def ip_score(events):
    accounts = len({e["user_id"] for e in events})
    if accounts == 1:
        return 0
    n = len(events)
    fail_rate = sum(e["result"] == "FAIL" for e in events) / n
    nosuch = sum(e["reason"] == "NO_SUCH_USER" for e in events)
    nosuch_rate = nosuch / n
    success_rate = sum(e["result"] == "SUCCESS" for e in events) / n
    asn, country = events[0]["asn"], events[0]["country"]
    hours = [e["ts"].hour for e in events]
    s = 0
    if nosuch >= 2 and nosuch_rate >= 0.3:        s += 3
    if accounts >= 3 and fail_rate >= 0.5:        s += 2
    if accounts >= 2 and fail_rate >= 0.5:        s += 1
    if has_burst(events):                         s += 2
    if any(k in e["user_agent"].lower() for e in events for k in BOT_KEYWORDS): s += 3
    if accounts >= 20:                            s += 1
    if success_rate >= 0.8:                       s -= 3
    if any(h in asn.lower() for h in HOSTING_HINT): s += 2
    if country != HOME_COUNTRY:                   s += 1
    if all(0 <= h <= 5 for h in hours):           s += 1
    return s


# ③ [2층] ASN/서브넷 기준 집계 — IP를 바꿔도 사업자/대역은 남는다
def aggregate(rows, key):
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    flagged = {}
    for name, events in groups.items():
        n = len(events)
        ips = len({e["src_ip"] for e in events})
        nosuch_rate = sum(e["reason"] == "NO_SUCH_USER" for e in events) / n
        success_rate = sum(e["result"] == "SUCCESS" for e in events) / n
        # 많은 IP가 모여 대량 시도 + 높은 없는계정 비율 + 낮은 성공률 → 분산 공격의 집합
        if ips >= 10 and n >= 20 and nosuch_rate >= 0.3 and success_rate < 0.2:
            flagged[name] = {"ips": ips, "attempts": n,
                             "nosuch_rate": nosuch_rate, "success_rate": success_rate}
    return groups, flagged


# ④ [3층] 글로벌 베이스라인 — 플랫폼 전체의 '없는 계정' 비율이 평소보다 치솟는가
def global_baseline(rows):
    by_hour = defaultdict(lambda: [0, 0])   # 시간대별 [없는계정, 전체]
    for r in rows:
        by_hour[r["ts"].hour][1] += 1
        if r["reason"] == "NO_SUCH_USER":
            by_hour[r["ts"].hour][0] += 1
    return by_hour


# ⑤ 실행
rows = load_logs()
by_ip = defaultdict(list)
for r in rows:
    by_ip[r["src_ip"]].append(r)

# 1층: IP 기준
ip_flagged = {ip for ip, ev in by_ip.items() if ip_score(ev) >= IP_THRESHOLD}

# 2층: ASN, 서브넷 기준
_, asn_flagged = aggregate(rows, "asn")
_, subnet_flagged = aggregate(rows, "subnet")
asn_flag_ips = {r["src_ip"] for r in rows if r["asn"] in asn_flagged}
subnet_flag_ips = {r["src_ip"] for r in rows if r["subnet"] in subnet_flagged}

# 최종: 세 층 중 하나라도 걸리면 탐지
detected_ips = ip_flagged | asn_flag_ips | subnet_flag_ips

# ⑥ 출력: low-and-slow가 각 층에서 어떻게 잡히는지 비교
ls_ips = {r["src_ip"] for r in rows if r["scenario"] == "low_slow"}
print(f"low-and-slow 사용 IP 수: {len(ls_ips)}")
print(f"  1층 IP 기준으로 잡힌 수   : {len(ls_ips & ip_flagged):>3} / {len(ls_ips)}   ← 거의 못 잡음")
print(f"  2층 ASN 집계로 잡힌 수     : {len(ls_ips & asn_flag_ips):>3} / {len(ls_ips)}   ← 여기서 걸림")

print("\n[ASN 집계에서 공격으로 걸린 사업자]")
print(f"{'ASN':<22}{'IP수':>5}{'시도':>6}{'없는계정':>9}{'성공률':>8}")
for name, m in sorted(asn_flagged.items(), key=lambda x: -x[1]["attempts"]):
    print(f"{name:<22}{m['ips']:>5}{m['attempts']:>6}{m['nosuch_rate']:>8.0%}{m['success_rate']:>8.0%}")

print("\n[글로벌 베이스라인: 시간대별 '없는 계정' 로그인 비율]")
bh = global_baseline(rows)
for h in range(24):
    bad, tot = bh[h]
    rate = bad / tot if tot else 0
    bar = "#" * int(rate * 40)
    print(f"  {h:02d}시  {rate:4.0%} {bar}")

# ⑦ 저장 (03_evaluate.py로 평가)
with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    fields = [k for k in rows[0] if k not in ("ts", "subnet")] + ["detected", "rules"]
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        layers = []
        if r["src_ip"] in ip_flagged:      layers.append("L1_ip")
        if r["src_ip"] in asn_flag_ips:    layers.append("L2_asn")
        if r["src_ip"] in subnet_flag_ips: layers.append("L2_subnet")
        writer.writerow({**r, "detected": int(r["src_ip"] in detected_ips),
                         "rules": "|".join(layers)})

print(f"\n저장 완료: {OUTPUT}")
