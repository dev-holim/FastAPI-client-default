from enum import Enum

class UserRole(str, Enum):

    USER = "user"
    ADMIN_JUNIOR = "admin_junior"
    ADMIN_SENIOR = "admin_senior"
    SUPER = "super"
    TESTER = "tester"
