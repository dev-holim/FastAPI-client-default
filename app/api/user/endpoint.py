from uuid import UUID
from http import HTTPStatus
from fastapi import APIRouter, Depends

from app.api.user.schema.reqest import SignUpRequest, SignInRequest
from app.api.user.schema.response import SignUpResponse, SignInResponse
from app.common.enums.user_status import UserLoginStatus
from app.core.service import Service
from app.core.service.user import *
from app.security.auth import Authorization

user_router = APIRouter(
    tags=['User']
)

@user_router.post(
    name="user:login",
    summary='로그인',
    description='로그인 프로세스',
    response_model=SignInResponse,
    status_code=HTTPStatus.OK,
    path='/login'
)
async def login_process(
    request: SignInRequest,
    service: Service = Depends(SignInService)
):
    return await service(**request.dict())


@user_router.post(
    name="user:register",
    summary='회원가입',
    description='회원 가입 프로세스',
    response_model=SignUpResponse,
    status_code=HTTPStatus.OK,
    path='/sign-up'
)
async def register_process(
    request: SignUpRequest,
    service: Service = Depends(AddUserService)
):
    return await service(**request.dict())


@user_router.get(
    name="user:check",
    summary='로그인 상태 체크',
    description='로그인 상태 체크',
    response_model=UserLoginStatus,
    status_code=HTTPStatus.OK,
    path='/check'
)
async def check_info(
    user_id: UUID = Depends(Authorization()),
    service: Service = Depends(CheckUserService)
):
    return await service(user_id=user_id)

# @user_router.post(
#     name="user:me",
#     summary='내 정보',
#     description='내 정보',
#     status_code=HTTPStatus.OK,
#     path='/me'
# )
# async def get_info(
#     user_id: UUID = Depends(Authorization()),
#     service: Service = Depends(SignInService)
# ):
#     return user_id
#     return service(
#         uid=user_id
#     )