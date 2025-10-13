from enum import Enum


# 유저 로그인 상태
class UserStatus(str, Enum):
    ACTIVE = 'ACTIVE'       # 활성 상태
    INACTIVE = 'INACTIVE'
    DELETED = 'DELETED'     # 탈퇴 상태
    SUSPENDED = 'SUSPENDED' # 정지 상태
    PENDING = 'PENDING'     # 승인 대기 상태
    BANNED = 'BANNED'       # 영구 정지 상태
    GUEST = 'GUEST'         # 게스트 상태
    VERIFIED = 'VERIFIED'   # 이메일 인증 완료 상태
    UNVERIFIED = 'UNVERIFIED' # 이메일 인증 대기 상태
    LOCKED = 'LOCKED'       # 계정 잠금 상태
    TEMPORARY = 'TEMPORARY' # 임시 상태
    ARCHIVED = 'ARCHIVED'   # 보관 상태
    SUSPICIOUS = 'SUSPICIOUS' # 의심스러운 상태


# 유저 로그인 상태
class UserLoginStatus(str, Enum):
    LOGIN = 'LOGIN'  # 로그인 상태
    LOGOUT = 'LOGOUT' # 로그아웃 상태
    NO_AUTH = 'NO_AUTH' # 회원 없음
