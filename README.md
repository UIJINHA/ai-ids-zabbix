# AI 기반 침입탐지시스템 (Zabbix + Isolation Forest + 룰)

서버의 운영 지표(CPU·네트워크·로그인 등)만으로 침입·이상 행위를 탐지하는 하이브리드 IDS.
**정상 데이터만으로 학습한 이상탐지 모델**과 **명시적 룰**을 결합해, 자원을 흔드는 공격과
로그에만 흔적이 남는 공격을 모두 잡는 것이 목표다.

> 이 문서는 시스템 전체를 설명하는 **설명서**다. 단계별 구축 기록은 [`docs/`](docs) 참고.

---

## 1. 한눈에 보기

- **무엇을?** 감시 대상 서버(VM2)의 지표를 탐지 서버(VM1)가 원격 수집 → 30분 단위로 요약 →
  Isolation Forest 모델과 룰로 매 5분 이상 여부를 판정한다.
- **왜 이렇게?** 공격 데이터는 미리 라벨링해 모으기 어렵다. 그래서 **"정상이 어떤 모습인지"만
  학습**하고, 그 정상에서 크게 벗어나면 이상으로 본다(비지도 이상탐지).
- **핵심 결론:** 모델 하나로는 부족하다. 여러 지표가 동시에 흔들리는 공격(DoS·채굴)은 모델이
  잘 잡지만, **단일 지표만 튀는 공격(무차별 대입·대역폭 유출)은 32개 지표의 평균 점수에서
  신호가 희석**되어 놓친다. 이를 **룰로 보완한 하이브리드**로 공격 6종을 모두 탐지했다.

---

## 2. 시스템 구성

| 구분 | 역할 | 주요 구성 | IP |
|---|---|---|---|
| **VM1** | 탐지 서버 + 공격/트래픽 발생 | Zabbix Server, MariaDB(`aiids`), Python(venv), cron | 192.168.199.10 |
| **VM2** | 감시 대상 | nginx, PHP, Zabbix Agent | 192.168.199.20 |

- 폐쇄망(내부 전용). 공격 실험은 VM1 → VM2 방향으로만.
- 접속: `ssh uijin@192.168.199.10`, 프로젝트 경로 `~/ai-ids-zabbix`.

---

## 3. 전체 데이터 흐름

```
 [VM2] Zabbix Agent ──지표──▶ [VM1] Zabbix Server ──(DB에 이력 저장)
                                        │
                                        │  Zabbix JSON-RPC API
                                        ▼
  (1) collect.py ──────────▶ MariaDB: metrics (원시 지표, 1분 간격)
                                        │
            ┌───────────────────────────┴───────────────────────────┐
            │ (학습 경로, 수동)                      (탐지 경로, 자동 5분) │
            ▼                                                        ▼
  (2) build_features.py                                 (4) detect_anomaly.py
       metrics→features (30분 창 집계)                    최근 90분 metrics를 즉석에서
            │                                             Feature로 만들어
            ▼                                              ├─ 모델 점수 판정
  (3) train_model.py                                       └─ 룰 판정
       features로 IsolationForest 학습                          │ 더 심각한 쪽 채택
            │                                                   ▼
            ▼                                          MariaDB: anomalies + detect.log
       model/iforest.pkl ──────────────(탐지에서 로드)──────────┘
```

- **학습 경로(2→3)**: 평소 한 번 돌려 모델을 만든다. 정상 데이터만 사용.
- **탐지 경로(4)**: cron이 5분마다 자동 실행. `build_features`를 따로 돌릴 필요 없이,
  `detect_anomaly.py`가 최근 데이터로 Feature를 즉석 생성해 판정한다.
- 정상 트래픽 생성기(`gen_traffic.sh`, `gen_login.sh`)가 VM2에 평상시 부하를 만들어,
  수집되는 "정상"이 실제 운영 환경처럼 보이게 한다.

---

## 4. 구성요소 (src/)

| 파일 | 역할 | 입력 → 출력 |
|---|---|---|
| `collect.py` | Zabbix API로 지표 수집 | Zabbix history → `metrics` 테이블 |
| `build_features.py` | 30분 창 집계로 Feature 생성 | `metrics` → `features` 테이블 |
| `train_model.py` | Isolation Forest 학습 | `features` → `model/*.pkl` |
| `detect_anomaly.py` | 실시간 탐지(모델+룰) | 최근 90분 `metrics` → `anomalies` + 로그 |
| `gen_traffic.sh` | 정상 웹 부하 발생(ab→PHP) | 시간대별 CPU/네트워크 변동 |
| `gen_login.sh` | 정상 SSH 로그인 발생 | ssh_ok 지표에 평상시 성공 로그인 |
| `eval_attack.py` | 과거 구간 사후 재점수화(검증 도구) | 전체 타임라인 scan |
| `evaluate.py` | 라벨된 공격 대상 성능 측정 | 탐지/미탐/오탐 → `tuning-log.csv` |
| `rebuild_clean_features.py` | 공격 구간 제외 Feature 재생성(재학습용) | `metrics` → `features` |
| `config.py` | DB·Zabbix 접속 설정 (git 제외, `config.example.py` 참고) | — |

### 4-1. collect.py — 수집
- Zabbix JSON-RPC API(`history.get`)로 최근 `COLLECT_MINUTES`분의 숫자형 아이템을 가져와
  `metrics`에 `INSERT IGNORE`(중복 방지)로 저장. cron이 5분마다 실행.
- 대상 호스트는 `config.TARGET_HOSTS`. Zabbix Agent의 폴링 주기 때문에 실제 저장은 **1분 간격**.

### 4-2. build_features.py — Feature 생성
- `metrics`의 10개 핵심 지표를 5분 간격으로 리샘플하고 **30분 롤링 창**으로
  평균·최대·표준편차를 계산 → 지표 10개 × 3 = 30개 + 시간주기(sin/cos) 2개 = **32개 Feature**.
- `features` 테이블을 DROP 후 재생성(통째로 다시 씀).

### 4-3. train_model.py — 학습
- `features` 전체(정상)로 `IsolationForest(n_estimators=200, contamination=0.01)` 학습.
- `model/iforest.pkl`, `scaler.pkl`, `feature_cols.json` 저장(git 제외).

### 4-4. detect_anomaly.py — 탐지 (핵심)
- 최근 90분 `metrics`를 즉석에서 Feature로 만들어 **마지막 30분 창** 한 줄을 판정.
- **모델 판정**: 이상점수 `score`가 낮을수록 이상. `< -0.06` → 위험, `< 0` → 경고.
- **룰 판정**(아래 7절). 최종 등급 = 모델·룰 중 **더 심각한 쪽**.
- 결과를 `anomalies` 테이블과 `results/detect.log`에 기록.

---

## 5. 데이터베이스 (MariaDB `aiids`)

| 테이블 | 내용 | 주요 컬럼 |
|---|---|---|
| `metrics` | 원시 지표(1분 간격) | host, item_key, clock, value |
| `features` | 30분 창 집계 Feature 32개 | clock, cpu_user_mean, …, hour_sin, hour_cos |
| `anomalies` | 탐지 결과 | time, host, score, grade, source, reason |

수집하는 10개 지표: `cpu_user, load1, mem, net_in, net_out, ssh_fail, ssh_ok, conn, synrecv, proc`

---

## 6. 탐지 로직 — 하이브리드

공격은 크게 두 종류이고, 각자 잘 잡는 방식이 다르다.

| 공격 유형 | 특징 | 잘 잡는 쪽 |
|---|---|---|
| 여러 지표를 동시에 흔듦 (DoS, 채굴) | cpu·conn·load 등 동시 급변 | **모델** |
| 단일 지표만 튐 (무차별 대입, 대역폭 유출) | ssh_fail만 / net_out만 급증 | **룰** |

- **왜 모델만으론 부족한가(희석):** Isolation Forest는 32개 Feature를 종합한 "고립 정도"로
  점수를 낸다. 한 지표가 아무리 극단적이어도 나머지 29개가 정상이면 점수가 정상 쪽으로
  희석된다. 실제로 데이터 유출 때 net_out이 평소의 200배(+600σ)였는데도 모델은 정상 판정했다.
- **룰로 보완:** 단일 지표형 공격에 명시적 임계 룰을 둔다.
  - `ssh_fail_mean ≥ 30` & `ssh_ok < 1` → 위험 (SSH 무차별 대입)
  - `synrecv_max ≥ 20` → 위험 (포트 스캔)
  - `net_out_mean ≥ 50MB` → 위험 / `≥ 25MB` → 경고 (데이터 유출)
- **최종 등급:** `max(모델 등급, 룰 등급)` — 둘 중 더 심각한 쪽을 택한다.

---

## 7. 자동화 (VM1 crontab)

| 주기 | 작업 | 용도 |
|---|---|---|
| 매 5분 (:00,:05…) | `collect.py` | 지표 수집 |
| 매 5분 (:02,:07…) | `detect_anomaly.py` | 자동 탐지(수집 2분 뒤) |
| 매 5분 | `gen_traffic.sh` | 정상 웹 부하 |
| 매 10분 | `gen_login.sh` | 정상 로그인 |

> ⚠️ VM1(노트북)이 절전/종료되면 수집·탐지가 함께 멈춘다. 운영 중에는 절전을 꺼둘 것.

---

## 8. 사용법

```bash
# 0) 최초 1회 설정
cp src/config.example.py src/config.py   # 토큰·DB비번 채우기
mysql aiids < sql/schema.sql             # metrics 테이블 생성
python -m venv venv && source venv/bin/activate
pip install pandas numpy scikit-learn joblib pymysql requests

# 1) 수집 (cron이 자동으로 하지만 수동 실행도 가능)
python src/collect.py

# 2) 학습 (정상 데이터가 쌓인 뒤 한 번)
python src/build_features.py
python src/train_model.py

# 3) 탐지 (cron이 5분마다 자동)
python src/detect_anomaly.py

# 4) 성능 측정 / 사후 검증 (프로젝트 루트에서)
PYTHONPATH=src python src/evaluate.py "메모" [DANGER_TH] [WARN_TH]
PYTHONPATH=src python src/eval_attack.py 2026-10-07T15:35:00 2026-10-07T16:45:00
```

---

## 9. 결과 요약

- 공격 6종(SSH 무차별 대입 v1·v2·v3, DoS 웹, 채굴형 CPU, 데이터 유출) **전부 탐지, 미탐 0.**
- DoS·채굴 = 모델이 [위험], 무차별 대입·유출 = 룰이 [위험]으로 포착.
- 오탐은 튜닝(모델 임계 -0.06)으로 실질 0 수준. 자세한 수치는 ↓

| 문서 | 내용 |
|---|---|
| [docs/07-탐지결과.md](docs/07-탐지결과.md) | 공격별 탐지 결과·근거 |
| [docs/08-튜닝.md](docs/08-튜닝.md) | 오탐/미탐 측정, 임계 튜닝, 재학습 실험 |
| [results/tuning-log.csv](results/tuning-log.csv) | 튜닝 실험 이력 |

---

## 10. 용어집

- **이상탐지(비지도)**: 공격 라벨 없이 "정상"만 학습하고, 정상에서 벗어난 정도로 이상 판단.
- **Isolation Forest**: 데이터를 무작위로 쪼개 빨리 고립되는 점일수록 이상으로 보는 알고리즘.
- **이상점수(score)**: `decision_function` 값. **낮을수록(음수) 이상**, 높을수록 정상.
- **Feature(특징)**: 원시 지표를 30분 창으로 요약한 숫자(평균/최대/표준편차 등) 32개.
- **30분 롤링 창**: 순간값의 노이즈 대신 "최근 30분의 패턴"을 보기 위한 집계 단위.
- **σ(시그마)**: 정상 대비 몇 표준편차 떨어졌는지. 기여 Feature 해석에 사용.
- **contamination**: 학습 데이터에 섞였다고 가정하는 이상 비율(여기선 0.01).
- **희석(dilution)**: 단일 지표만 극단적이어도 나머지 정상 지표 때문에 종합 점수가
  정상 쪽으로 묻히는 현상. 이 프로젝트가 룰을 도입한 이유.

---

## 11. 디렉터리 구조

```
ai-ids-zabbix/
├── README.md              # (이 문서) 시스템 설명서
├── docs/                  # 단계별 구축·결과 기록 (01~08)
├── src/                   # 수집·학습·탐지·검증 스크립트
├── sql/schema.sql         # metrics 테이블 스키마
├── model/                 # 학습된 모델 (git 제외)
└── results/               # 로그, tuning-log.csv
```

### 문서 색인 (docs/)
01 환경구축 · 02 Zabbix 설치 · 03 데이터수집 · 04 실습환경설계 ·
05 탐지대상설계 · 06 진행상황(인수인계) · 07 탐지결과 · 08 튜닝
