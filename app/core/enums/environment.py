from enum import Enum

class Environment(str, Enum):
    """환경 타입 정의"""
    LOCAL = "local"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
