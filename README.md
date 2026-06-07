# Linux Web Log SQL Analyzer

Linux 웹 서버 access log와 SQL 실행 로그를 SQLite에 적재하고 SQL 집계로 트래픽, 에러, 보안 의심 패턴, 느린 쿼리를 분석하는 포트폴리오 프로젝트입니다.

기존 Linux 운영 프로젝트와 연결해 “로그를 DB화하고, 지표로 판단하고, 운영 리포트로 남기는 흐름”을 보여주는 것이 목표입니다.

## What I Built / 만든 것

nginx·Apache access log와 SQL 실행 로그를 공통 데이터 모델로 정규화해 SQLite에 저장하고, CLI 명령과 FastAPI 대시보드에서 트래픽·오류·보안 의심 패턴·느린 SQL을 조회할 수 있게 만들었습니다.

## Main Features / 주요 기능

- nginx/apache common, combined access log 파싱
- MySQL slow query log와 단순 SQL execution log 파싱
- SQLite schema 자동 생성
- 같은 파일/source line 로그 재적재 중복 방지 및 skipped count 표시
- IP, path, status code, user-agent, 시간대별 집계
- 느린 SQL Top N, 쿼리 유형, 테이블별 집계
- 4xx/5xx 에러 급증 후보 확인
- 과다 요청 IP 탐지
- 관리자/로그인 URL 접근 패턴 확인
- CSV/JSON export
- FastAPI 대시보드 선택 실행
- Access Logs / SQL Logs 탭형 대시보드
- KPI 카드, 필터 폼, 상태/시간대 막대 차트
- token/password/api_key/session query value 마스킹
- HTML escape와 parameterized SQL 기반 안전한 조회
- 샘플 로그와 단위 테스트 포함

## Development / 개발 방식

```text
log file
   ↓
format-specific parser
   ↓
normalized record and masking
   ↓
SQLite insert with source/line deduplication
   ↓
parameterized SQL aggregation
   ├── CLI summary/export
   └── FastAPI dashboard/API
```

- access log와 SQL log parser를 분리하고 결과를 각각 `access_logs`, `sql_logs` schema로 정규화했습니다.
- `source + line_no` 기준으로 같은 로그 파일을 다시 적재해도 중복 row를 만들지 않습니다.
- token, password, api key, session query value는 저장·표시 단계에서 마스킹합니다.
- 사용자 필터는 parameterized SQL로 처리하고 원본 로그를 웹에 표시할 때 HTML escape를 적용합니다.
- 집계 SQL과 화면 표현을 분리해 같은 분석 결과를 CLI, CSV/JSON, 웹 API에서 재사용합니다.
- parser, ingest, query, export, web endpoint를 샘플 로그 기반 단위 테스트로 검증합니다.

## Quick Start / 빠른 시작

Python 3.10 이상을 지원합니다. CI는 Python 3.10과 3.12에서 테스트와 Docker smoke test를 실행합니다.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[web]"

web-log-sql init --db data/logs.db
web-log-sql ingest samples/nginx-access.log --db data/logs.db
web-log-sql ingest-sql samples/sql-execution.log --db data/logs.db
web-log-sql ingest-sql samples/mysql-slow.log --db data/logs.db
web-log-sql summary --db data/logs.db
web-log-sql sql-summary --db data/logs.db
web-log-sql search-access --db data/logs.db --status 401 --format json
web-log-sql search-sql --db data/logs.db --statement-type SELECT --min-duration-ms 100
web-log-sql export parse-errors --db data/logs.db --format json
web-log-sql export top-paths --db data/logs.db --format csv
web-log-sql export slow-sql --db data/logs.db --format json
web-log-sql serve --db data/logs.db --host 127.0.0.1 --port 18080
```

설치 없이 소스 트리에서 직접 실행하려면 `PYTHONPATH=src`를 지정합니다.

```bash
PYTHONPATH=src python3 -m linux_web_log_sql_analyzer.cli ingest samples/nginx-access.log --db data/logs.db
```

## CLI / 명령줄 사용법

```text
web-log-sql init --db data/logs.db
web-log-sql ingest samples/nginx-access.log --db data/logs.db
web-log-sql ingest-sql samples/sql-execution.log --db data/logs.db
web-log-sql summary --db data/logs.db
web-log-sql sql-summary --db data/logs.db
web-log-sql search-access --db data/logs.db --status 401 --format csv
web-log-sql search-sql --db data/logs.db --statement-type SELECT --min-duration-ms 100 --format json
web-log-sql export parse-errors --db data/logs.db --format json
web-log-sql export status --db data/logs.db --format json
web-log-sql export suspicious-ips --db data/logs.db --format csv
web-log-sql export slow-sql --db data/logs.db --format json
web-log-sql export sql-types --db data/logs.db --format csv
web-log-sql serve --db data/logs.db
```

Dashboard API examples:

```text
GET /api/v1/logs?status=401&path=/login&limit=20
GET /api/v1/sql-logs?statement_type=SELECT&min_duration_ms=100
GET /api/v1/metrics/slow-sql?limit=10
```

## Search Reports / 검색 리포트

`search-access`와 `search-sql`은 기존 분석 결과를 조건 필터로 바로 조회하는 명령입니다.  
운영 이슈를 확인할 때 전체 집계보다 빠르게 특정 요청이나 SQL 패턴을 볼 수 있습니다.

`parse-errors`는 access log와 SQL log의 파싱 실패 행을 한 번에 모아 보여줍니다.
웹 대시보드에도 `Parse Errors` 탭이 있습니다.

## Data Model / 데이터 모델

```text
access_logs
- id
- source
- line_no
- remote_addr
- method
- path
- query
- protocol
- status
- bytes_sent
- referrer
- user_agent
- requested_at
- raw_line
- parse_error
- created_at

sql_logs
- id
- source
- line_no
- statement
- statement_type
- table_name
- duration_ms
- lock_time_ms
- rows_sent
- rows_examined
- executed_at
- raw_entry
- parse_error
- created_at
```

`raw_line`은 원본 확인을 위해 저장하지만, 웹 화면에서는 HTML escape 처리합니다. SQL은 parameterized query만 사용합니다.

## Test / 테스트

```bash
pip install -e ".[web,test]"
python3 -m unittest discover -s tests
```

설치 없이 실행:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Build / 빌드

온라인 환경이나 CI에서는 격리 빌드를 사용합니다.

```bash
pip install build
python3 -m build
```

네트워크가 막힌 로컬 환경에서는 build backend를 먼저 설치한 뒤 격리 없이 검증할 수 있습니다.

```bash
pip install build setuptools wheel
python3 -m build --no-isolation
```

## Docker / Docker 실행

```bash
docker compose up --build
```

대시보드 주소:

```text
http://127.0.0.1:18080
```

컨테이너 이미지는 샘플 access log와 SQL log를 `data/dashboard.db`에 적재한 뒤 대시보드를 실행합니다.

## License / 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
