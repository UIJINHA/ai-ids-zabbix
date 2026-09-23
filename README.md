# AI 기반 IDS 구축 (Zabbix + Python + Isolation Forest)

Zabbix로 수집한 서버 지표를 Python으로 가공하고, Isolation Forest로 이상 행위를 탐지하는 침입탐지시스템 구축 실습 기록.

## 개요
- 목적: 라벨링된 공격 데이터 없이, 정상 데이터만으로 이상 징후를 탐지
- 환경: Ubuntu (VMware Workstation), Zabbix, MariaDB, Python 3

## 구성
| 구분 | 역할 | IP |
|---|---|---|
| VM1 | 탐지 서버 (Zabbix Server, MariaDB, Python) | 192.168.199.10 |
| VM2 | 감시 대상 서버 (Zabbix Agent) | 192.168.199.20 |

## 데이터 흐름
Zabbix Agent → Zabbix Server → Python 수집 → MariaDB → Feature 생성 → Isolation Forest → 탐지 결과 저장

## 진행 상황
- [x] VMware / Ubuntu 설치
- [ ] 고정 IP 및 SSH 설정
- [ ] VM2 구축
- [ ] Zabbix 설치 및 연동
- [ ] Python 데이터 수집
- [ ] Feature 생성
- [ ] 모델 학습
- [ ] 공격 시나리오 및 임계값 튜닝

## 문서
- docs/ 아래에 단계별 구축 기록
