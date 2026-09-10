from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.exceptions import ECWFException


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ECWFException)
    async def ecwf_exception_handler(request: Request, exc: ECWFException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message},
        )
