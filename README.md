# FastAPI Default Starter

이 레포지토리는 FastAPI 기반의 프로젝트를 빠르게 시작할 수 있도록 만든 기본 템플릿입니다.<br/>
바로 실행 가능한 최소 구성과 실무에서 자주 쓰는 폴더 구조, 설정 분리를 포함하고 있으며, 계속해서 확장/개선될 예정입니다.

### 주요 특징
- **바로 실행**: `uvicorn`으로 즉시 기동 가능한 진입점(`main.py`).
- **모듈화된 설정**: 환경(`APP_ENV`)에 따라 로딩되는 설정과 `.env` 지원.
- **구조화된 레이어**: API 라우터, 설정, 보안, 공용 상수/열거형 등 디렉터리 분리.
- **문서화 준비**: OpenAPI 태그, Swagger UI 정렬 설정 포함.

### 요구 사항
- Python 3.13+
- `uv` 또는 `pip`로 의존성 설치 가능

### 설치 및 실행
1) 의존성 설치
```bash
uv sync
# 또는
pip install -r <(uv pip compile pyproject.toml)
```

2) 로컬 실행
```bash
uv run uvicorn main:app --reload
# 또는
uvicorn main:app --reload
```

실행 후:
- 헬스 체크: `GET /health` → `{ "status": "ok" }`
- 문서: `http://127.0.0.1:8000/docs`

### 환경 설정
- 환경 변수 `APP_ENV`로 실행 환경을 지정합니다. 기본값은 `LOCAL`입니다.
- `LOCAL`, `DEVELOPMENT` 환경에서는 `.env` 파일을 자동으로 로드합니다.
- 대표 설정들:
  - `APP_SECRET_KEY` (필수, 최소 32자)
  - CORS: `CORS_ALLOWED_ORIGINS`, `CORS_ALLOWED_METHODS`, `CORS_ALLOWED_HEADERS`
  - Redis: `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` 등

예시 `.env` (로컬 개발):
```bash
APP_ENV=LOCAL
APP_SECRET_KEY=your-32-bytes-or-longer-secret-key................................
CORS_ALLOWED_ORIGINS=*
CORS_ALLOWED_METHODS=*
CORS_ALLOWED_HEADERS=*
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

### 프로젝트 구조 개요
```text
FastAPI-default/
├─ main.py                   # 앱 기동(엔트리 포인트), /health 엔드포인트
├─ app/
│  ├─ __init__.py           # 앱 팩토리(create_app), lifespan 훅, CORS/라우터 등록
│  ├─ api/
│  │  └─ user/
│  │     ├─ endpoint.py     # 사용자 관련 API 예시 (/users/login 스텁)
│  │     └─ schema/         # 요청/응답 스키마 위치
│  ├─ config/
│  │  ├─ app.py             # 앱 전역 설정(AppConfig)
│  │  ├─ environment.py     # 환경 구분/로딩 로직(EnvironmentConfig)
│  │  ├─ cors.py            # CORS 설정(CORSConfig)
│  │  └─ cache.py           # Redis 설정(RedisConfig)
│  ├─ security/
│  │  └─ cors.py            # FastAPI CORS 미들웨어 등록 함수
│  ├─ core/                 # 공통 Enum 등 코어 요소
│  └─ common/               # 공통 유틸/타입/열거형
└─ pyproject.toml           # 의존성 및 메타데이터
```

### 라우팅과 문서
- `app/__init__.py`의 `create_app`에서 `include_routers(app)`가 호출되며, OpenAPI 태그와 Swagger UI 정렬(`operationsSorter: method`)이 적용됩니다.
- 사용자 예시 라우터: `POST /users/login` (스텁)

### CORS 정책
- `app/security/cors.py`에서 FastAPI CORS 미들웨어를 등록합니다.
- 허용 목록은 `app/config/cors.py`의 `CORSConfig`로 관리되며, 환경 변수로 오버라이드 가능합니다.

### Redis 설정
- `app/config/cache.py`의 `RedisConfig`를 통해 호스트/포트/DB/비밀번호 등 구성.
- 연결 문자열은 `redis://` 스킴으로 자동 생성됩니다.

### 확장 로드맵(계속 추가 예정)
- 데이터베이스 초기화(`init_rdb`), 캐시 UoW 초기화(`init_cache`) 연계
- 예시 도메인/리포지터리/서비스 레이어 추가
- 인증/인가, 세션/토큰 유틸 추가
- 테스트 템플릿 및 CI 워크플로

필요한 구성/예시를 이 템플릿에 지속적으로 추가할 예정입니다. 사용 중 개선 아이디어나 요청 사항이 있다면 자유롭게 제안해주세요.


