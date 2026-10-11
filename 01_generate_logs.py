# ① 기본 설정
import csv
import random
from collections import Counter
from datetime import datetime, timedelta

random.seed(42)                  # 실행할 때마다 같은 데이터가 나오도록 고정
START = datetime(2026, 10, 1)    # 하루치 로그의 시작 시각
OUTPUT = "login_logs.csv"

BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928N) Chrome/129.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1",
]
BOT_UA = "python-requests/2.31.0"   # 공격 도구에서 흔히 보이는 User-Agent

VALID_USERS = [f"user{i:04d}" for i in range(1, 1001)]  # 실제 가입 회원 1000명
logs = []


# ② 공통 함수
def rand_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def add_log(ts, user, ip, ua, success, reason, label, scenario):
    logs.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user,
        "src_ip": ip,
        "user_agent": ua,
        "result": "SUCCESS" if success else "FAIL",
        "reason": reason,        # OK / WRONG_PASSWORD / NO_SUCH_USER
        "label": label,          # 정답 (normal / attack), 평가 때만 사용
        "scenario": scenario,    # 어떤 상황에서 생긴 로그인지 (분석용)
    })


# ③ 정상 사용자
def gen_normal_users():
    for user in random.sample(VALID_USERS, 800):
        home_ip = rand_ip()                  # 사용자마다 자주 쓰는 IP
        ua = random.choice(BROWSER_UA)
        for _ in range(random.randint(1, 3)):          # 하루 1~3번 접속
            ts = START + timedelta(seconds=random.randint(0, 86399))
            fails = random.choices([0, 1, 2], weights=[85, 10, 5])[0]
            for _ in range(fails):                     # 가끔 비밀번호를 틀림
                add_log(ts, user, home_ip, ua, False, "WRONG_PASSWORD", "normal", "normal")
                ts += timedelta(seconds=random.randint(5, 30))
            add_log(ts, user, home_ip, ua, True, "OK", "normal", "normal")


# ④ 오탐 유발 상황 2가지
def gen_office_nat():
    office_ip = "203.0.113.10"   # 회사 공인 IP (직원 전체가 공유)
    for user in random.sample(VALID_USERS, 60):
        ts = START + timedelta(hours=9, seconds=random.randint(0, 1800))  # 09:00~09:30 출근 시간
        if random.random() < 0.15:
            add_log(ts, user, office_ip, BROWSER_UA[0], False, "WRONG_PASSWORD", "normal", "office_nat")
            ts += timedelta(seconds=random.randint(5, 20))
        add_log(ts, user, office_ip, BROWSER_UA[0], True, "OK", "normal", "office_nat")


def gen_forgetful_user():
    user, ip = "user0007", rand_ip()
    ts = START + timedelta(hours=21)
    for _ in range(8):           # 비밀번호가 기억나지 않아 8번 연속 실패
        add_log(ts, user, ip, BROWSER_UA[1], False, "WRONG_PASSWORD", "normal", "forgetful")
        ts += timedelta(seconds=random.randint(10, 40))


# ⑤ 공격: 유출 계정 대입
def make_leaked_credential():
    r = random.random()
    if r < 0.70:     # 70%: 다른 사이트에서 유출된 ID라 이 쇼핑몰에는 없음
        fake = random.choice(["kim", "lee", "park", "choi", "jung"]) + str(random.randint(100, 99999))
        return fake, False, "NO_SUCH_USER"
    user = random.choice(VALID_USERS)
    if r < 0.97:     # 27%: 가입한 회원이지만 비밀번호가 다름
        return user, False, "WRONG_PASSWORD"
    return user, True, "OK"   # 3%: 비밀번호 재사용으로 로그인 성공 (계정 탈취)


def gen_attack_burst():
    for hour in [2, 14, 23]:   # 봇 IP 3개, 각각 다른 시간대
        ip = f"45.155.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ts = START + timedelta(hours=hour, minutes=random.randint(0, 50))
        for _ in range(150):   # 1~3초 간격으로 150건
            user, ok, reason = make_leaked_credential()
            add_log(ts, user, ip, BOT_UA, ok, reason, "attack", "burst")
            ts += timedelta(seconds=random.randint(1, 3))


def gen_attack_distributed():
    for _ in range(50):        # 프록시 IP 50개
        ip = rand_ip()
        ua = random.choice(BROWSER_UA)        # 브라우저로 위장
        for _ in range(random.randint(5, 8)): # IP당 하루 5~8건만 시도
            ts = START + timedelta(seconds=random.randint(0, 86399))
            user, ok, reason = make_leaked_credential()
            add_log(ts, user, ip, ua, ok, reason, "attack", "distributed")


# ⑥ 실행 및 저장
gen_normal_users()
gen_office_nat()
gen_forgetful_user()
gen_attack_burst()
gen_attack_distributed()

logs.sort(key=lambda r: r["timestamp"])   # 실제 로그처럼 시간순 정렬

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
    writer.writeheader()
    writer.writerows(logs)

print(f"총 로그 수: {len(logs)}")
print("시나리오별:", Counter(r["scenario"] for r in logs))
print("결과별:", Counter(r["result"] for r in logs))
print("공격으로 로그인 성공(계정 탈취):",
      sum(1 for r in logs if r["label"] == "attack" and r["result"] == "SUCCESS"))
