# ① 기본 설정: 정성 지표(지역/ASN/시간)와 고객 오타를 추가한 보강 버전
import csv
import random
from collections import Counter
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 10, 1)
OUTPUT = "login_logs_trend.csv"

BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928N) Chrome/129.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1",
]
BOT_UA = "python-requests/2.31.0"

# 정성 지표 재료: ASN(인터넷 사업자)과 국가. 일반 고객은 국내 ISP, 공격은 해외 호스팅이 많음
RESIDENTIAL_ASN = ["AS4766 KT", "AS3786 LGU+", "AS9318 SKB", "AS9644 SKT-Mobile"]
HOSTING_ASN = ["AS49505 Selectel", "AS14061 DigitalOcean", "AS51167 Contabo",
               "AS200019 AlexHost", "AS16509 Amazon-AWS"]
FOREIGN = ["RU", "NL", "US", "DE", "VN", "BR", "UA", "RO"]

VALID_USERS = [f"user{i:04d}" for i in range(1, 1001)]
logs = []


# ② 공통 함수: country, asn 칸 추가
def rand_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def add_log(ts, user, ip, ua, success, reason, label, scenario, country, asn):
    logs.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user, "src_ip": ip, "user_agent": ua,
        "result": "SUCCESS" if success else "FAIL", "reason": reason,
        "country": country, "asn": asn,          # ← 정성 판단용 맥락
        "label": label, "scenario": scenario,     # ← 정답 (평가 전용)
    })


def typo_id():   # 고객이 자기 아이디를 잘못 입력 → 존재하지 않는 계정
    return f"user{random.randint(1, 9999):04d}x"


# ③ 정상 사용자: 대부분 국내 거주망, 가끔 해외(출장)·가끔 자기 아이디 오타
def gen_normal_users():
    for user in random.sample(VALID_USERS, 800):
        home_ip = rand_ip()
        ua = random.choice(BROWSER_UA)
        asn = random.choice(RESIDENTIAL_ASN)
        country = "KR" if random.random() < 0.95 else random.choice(FOREIGN)  # 5% 해외
        for _ in range(random.randint(1, 3)):
            ts = START + timedelta(seconds=random.randint(0, 86399))
            fails = random.choices([0, 1, 2], weights=[85, 10, 5])[0]
            typo_done = False
            for _ in range(fails):
                # 한 세션에 최대 1번만 아이디 오타(현실적으로 아이디를 두 번 다르게 틀리긴 어려움)
                if not typo_done and random.random() < 0.3:
                    add_log(ts, typo_id(), home_ip, ua, False, "NO_SUCH_USER", "normal", "normal", country, asn)
                    typo_done = True
                else:
                    add_log(ts, user, home_ip, ua, False, "WRONG_PASSWORD", "normal", "normal", country, asn)
                ts += timedelta(seconds=random.randint(5, 30))
            add_log(ts, user, home_ip, ua, True, "OK", "normal", "normal", country, asn)


# ④ 오탐 유발 상황
def gen_office_nat():
    office_ip, asn = "203.0.113.10", "AS9848 CorpNet-KR"   # 회사 전용망(거주망도 호스팅도 아님)
    for user in random.sample(VALID_USERS, 60):
        ts = START + timedelta(hours=9, seconds=random.randint(0, 1800))
        if random.random() < 0.15:
            add_log(ts, user, office_ip, BROWSER_UA[0], False, "WRONG_PASSWORD", "normal", "office_nat", "KR", asn)
            ts += timedelta(seconds=random.randint(5, 20))
        add_log(ts, user, office_ip, BROWSER_UA[0], True, "OK", "normal", "office_nat", "KR", asn)


def gen_forgetful_user():
    user, ip, asn = "user0007", rand_ip(), random.choice(RESIDENTIAL_ASN)
    ts = START + timedelta(hours=21)
    for _ in range(8):
        add_log(ts, user, ip, BROWSER_UA[1], False, "WRONG_PASSWORD", "normal", "forgetful", "KR", asn)
        ts += timedelta(seconds=random.randint(10, 40))


# ⑤ 공격
def make_leaked_credential():
    r = random.random()
    if r < 0.70:
        fake = random.choice(["kim", "lee", "park", "choi", "jung"]) + str(random.randint(100, 99999))
        return fake, False, "NO_SUCH_USER"
    user = random.choice(VALID_USERS)
    if r < 0.97:
        return user, False, "WRONG_PASSWORD"
    return user, True, "OK"


def gen_attack_burst():   # 시끄러운 공격: 봇 UA + 해외 호스팅
    for hour in [2, 14, 23]:
        ip = f"45.155.{random.randint(0, 255)}.{random.randint(1, 254)}"
        asn, country = random.choice(HOSTING_ASN), random.choice(["RU", "NL", "UA"])
        ts = START + timedelta(hours=hour, minutes=random.randint(0, 50))
        for _ in range(150):
            user, ok, reason = make_leaked_credential()
            add_log(ts, user, ip, BOT_UA, ok, reason, "attack", "burst", country, asn)
            ts += timedelta(seconds=random.randint(1, 3))


def gen_attack_distributed():   # 분산 공격: 브라우저 위장, 호스팅 60% / 거주형 프록시 40%
    for _ in range(50):
        ip = rand_ip()
        ua = random.choice(BROWSER_UA)
        if random.random() < 0.6:
            asn, country = random.choice(HOSTING_ASN), random.choice(FOREIGN)
        else:
            asn, country = random.choice(RESIDENTIAL_ASN), random.choice(FOREIGN)  # 거주형 프록시
        for _ in range(random.randint(5, 8)):
            ts = START + timedelta(seconds=random.randint(0, 86399))
            user, ok, reason = make_leaked_credential()
            add_log(ts, user, ip, ua, ok, reason, "attack", "distributed", country, asn)


def gen_attack_stealth():   # 은밀한 공격: 유효 계정 2개만 조용히, 정량 규칙을 피하도록 설계
    for _ in range(10):
        ip = rand_ip()
        ua = random.choice(BROWSER_UA)                 # 브라우저 위장 → 봇 UA 신호 회피
        asn = random.choice(HOSTING_ASN)               # 단, 데이터센터에서 접속 (정성 단서)
        country = random.choice(FOREIGN)
        targets = random.sample(VALID_USERS, 2)        # 계정 2개만 → S1/S2 임계값 회피
        for user in targets:
            ts = START + timedelta(hours=random.randint(2, 4), seconds=random.randint(0, 3600))  # 새벽
            add_log(ts, user, ip, ua, False, "WRONG_PASSWORD", "attack", "stealth", country, asn)


# ⑤-2 최신 트렌드: low-and-slow(저속 분산). IP를 대량 교체하며 IP당 1~2번만,
#      하루 종일 흩뿌려 시간·IP 기준 임계값을 전부 회피한다.
PROXY_ASN = ["AS9009 M247", "AS206092 IPXO", "AS62240 Clouvider"]  # 상용 프록시 네트워크

def gen_attack_low_slow():
    for _ in range(90):                         # IP 90개를 돌려씀
        ip = rand_ip()
        ua = random.choice(BROWSER_UA)          # 브라우저 위장
        asn = random.choice(PROXY_ASN)
        country = random.choice(FOREIGN + ["KR", "KR"])  # 일부는 국내처럼 위장
        for _ in range(random.randint(1, 2)):   # IP당 1~2번만 → IP 기준 탐지 회피
            ts = START + timedelta(seconds=random.randint(0, 86399))  # 24시간 전체에 분산
            user, ok, reason = make_leaked_credential()
            add_log(ts, user, ip, ua, ok, reason, "attack", "low_slow", country, asn)


# ⑥ 실행 및 저장
for gen in (gen_normal_users, gen_office_nat, gen_forgetful_user,
            gen_attack_burst, gen_attack_distributed, gen_attack_stealth,
            gen_attack_low_slow):
    gen()

logs.sort(key=lambda r: r["timestamp"])
with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
    writer.writeheader()
    writer.writerows(logs)

print(f"총 로그 수: {len(logs)}")
print("시나리오별:", dict(Counter(r["scenario"] for r in logs)))
print("low_slow 로그 수:", sum(1 for r in logs if r["scenario"] == "low_slow"),
      "/ 사용 IP 수:", len({r["src_ip"] for r in logs if r["scenario"] == "low_slow"}))
