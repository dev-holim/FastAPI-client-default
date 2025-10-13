from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_cors_kwargs


def include_cors_middleware(app: FastAPI):
    cors_kwargs = get_cors_kwargs()
    
    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        **cors_kwargs
    )
