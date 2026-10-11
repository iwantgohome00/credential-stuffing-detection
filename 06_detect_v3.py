# ① 기본 설정: 정량 + 정성 신호를 하나의 위험 점수로 통합
import csv
from collections import defaultdict
from datetime import datetime, timedelta

INPUT = "login_logs_rich.csv"
OUTPUT = "detections_v3.csv"

WINDOW = timedelta(minutes=5)
MAX_IN_WINDOW = 10
BOT_KEYWORDS = ["python-requests", "curl", "wget", "go-http-client"]
HOSTING_HINT = ["selectel", "digitalocean", "contabo", "alexhost", "aws", "amazon"]  # 데이터센터 ASN 단서
HOME_COUNTRY = "KR"
SCORE_THRESHOLD = 4


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
    times = sorted(e["ts"] for e in events)
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > WINDOW:
            start += 1
        if end - start + 1 >= MAX_IN_WINDOW:
            return True
    return False


# ② IP별 특징: 정량(횟수·비율)과 정성(ASN·국가·시간대) 재료를 함께 추출
def features(events):
    n = len(events)
    hours = [e["ts"].hour for e in events]
    return {
        "attempts": n,
        "accounts": len({e["user_id"] for e in events}),
        "fail_rate": sum(e["result"] == "FAIL" for e in events) / n,
        "nosuch_count": sum(e["reason"] == "NO_SUCH_USER" for e in events),
        "nosuch_rate": sum(e["reason"] == "NO_SUCH_USER" for e in events) / n,
        "success_rate": sum(e["result"] == "SUCCESS" for e in events) / n,
        "burst": has_burst(events),
        "bot_ua": any(k in e["user_agent"].lower() for e in events for k in BOT_KEYWORDS),
        # 정성 재료
        "is_hosting": any(h in events[0]["asn"].lower() for h in HOSTING_HINT),
        "is_foreign": events[0]["country"] != HOME_COUNTRY,
        "night_only": all(0 <= h <= 5 for h in hours),
    }


# ③ 위험 점수: 정량 신호(S)와 정성 신호(Q)를 한 점수로 합산, 정상 패턴은 감점(D)
def score(f):
    if f["accounts"] == 1:
        return 0, 0, ["EXCLUDE_single_account"]   # 계정 1개 반복 → 크리덴셜 스터핑 아님(별도 처리)

    quant, qual, why = 0, 0, []
    # --- 정량(Quantitative) ---
    if f["nosuch_count"] >= 2 and f["nosuch_rate"] >= 0.3:
        quant += 3; why.append("S1_nosuch_user(+3)")
    if f["accounts"] >= 3 and f["fail_rate"] >= 0.5:
        quant += 2; why.append("S2_multi_account_fail(+2)")
    if f["accounts"] >= 2 and f["fail_rate"] >= 0.5:
        quant += 1; why.append("S6_low_volume_fail(+1)")   # 계정 2개짜리 은밀한 공격을 위한 약한 신호
    if f["burst"]:
        quant += 2; why.append("S3_velocity(+2)")
    if f["bot_ua"]:
        quant += 3; why.append("S4_bot_ua(+3)")
    if f["accounts"] >= 20:
        quant += 1; why.append("S5_many_accounts(+1)")
    if f["success_rate"] >= 0.8:
        quant -= 3; why.append("D1_high_success(-3)")      # 대부분 성공 → 공용 IP 등 정상
    # --- 정성(Qualitative) ---
    if f["is_hosting"]:
        qual += 2; why.append("Q1_datacenter_asn(+2)")     # 실제 고객은 데이터센터에서 로그인하지 않음
    if f["is_foreign"]:
        qual += 1; why.append("Q2_foreign_country(+1)")    # 국내 쇼핑몰 기준 해외 접속은 약한 단서
    if f["night_only"]:
        qual += 1; why.append("Q3_night_only(+1)")         # 접속이 전부 새벽 시간대
    return quant + qual, quant, why    # (총점, 정량만의 소계, 근거)


# ④ 실행
rows = load_logs()
by_ip = group_by_ip(rows)

result, watch = {}, []
for ip, events in by_ip.items():
    f = features(events)
    total, quant, why = score(f)
    result[ip] = (total, quant, why, f)
    if f["accounts"] == 1 and f["fail_rate"] == 1 and f["attempts"] >= 5:
        watch.append((ip, events[0]["user_id"], f["attempts"]))

flagged = {ip for ip, (total, _, _, _) in result.items() if total >= SCORE_THRESHOLD}

# ⑤ 출력
print(f"전체 IP 수: {len(by_ip)} / 탐지된 IP 수: {len(flagged)} (임계값 {SCORE_THRESHOLD}점)\n")
print(f"{'IP':<17}{'총점':>4}{'정량':>4}{'시도':>5}{'계정':>5}{'국가':>5}  {'ASN':<18}신호")
for ip in sorted(result, key=lambda x: -result[x][0]):
    total, quant, why, f = result[ip]
    if ip in flagged or 1 <= total < SCORE_THRESHOLD:
        mark = "탐지" if ip in flagged else "통과"
        asn, ctry = by_ip[ip][0]["asn"], by_ip[ip][0]["country"]
        tags = ",".join(w.split("(")[0] for w in why)
        print(f"{ip:<17}{total:>4}{quant:>4}{f['attempts']:>5}{f['accounts']:>5}{ctry:>5}  {asn:<18}[{mark}] {tags}")

# 정성 신호 덕분에 잡힌 IP(= 정량만으로는 임계값 미달이던 IP)
print("\n[정성 신호가 결정적이었던 탐지: 정량만으로는 놓쳤을 공격]")
for ip in sorted(flagged):
    total, quant, why, f = result[ip]
    if quant < SCORE_THRESHOLD:
        why_q = ", ".join(w for w in why if w.startswith("Q"))
        print(f"  {ip:<16} {by_ip[ip][0]['scenario']:<9} 정량 {quant}점 → 정성 추가 후 {total}점  ({why_q})")

print("\n[관찰 대상: 단일 계정 반복 실패]")
for ip, user, n in watch:
    print(f"  {ip:<16} {user} {n}회 연속 실패")

# ⑥ 저장
with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    fields = [k for k in rows[0] if k != "ts"] + ["detected", "rules", "score"]
    writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        total, _, why, _ = result[r["src_ip"]]
        writer.writerow({**r, "detected": int(r["src_ip"] in flagged),
                         "rules": "|".join(why), "score": total})

print(f"\n저장 완료: {OUTPUT}")
