import dataclasses
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import parser
from .models import TerminationReason

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _serialize_connection(conn) -> dict:
    d = dataclasses.asdict(conn)
    # TerminationReason is a str-enum; asdict preserves the enum instance,
    # so we explicitly extract its .value (e.g. "FIN", "RST", "Timeout") or None.
    tr = d.get("tcp_termination")
    if tr is not None:
        d["tcp_termination"] = tr.value if isinstance(tr, TerminationReason) else str(tr)
    return d


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    try:
        data = await file.read()
        connections = parser.parse(data)
        return {"connections": [_serialize_connection(c) for c in connections]}
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Internal server error."})
