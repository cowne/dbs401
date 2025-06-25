from fastapi import FastAPI, Request
from pydantic import BaseModel
from detector import check_exploit_sqli
from db import run_query
from fastapi.responses import JSONResponse

app = FastAPI()

class SQLQuery(BaseModel):
    query: str

@app.post("/check_and_run")
async def check_and_run(data: SQLQuery):
    if check_exploit_sqli(data.query):
        return JSONResponse(status_code=403, content={"error": "SQL Injection detected!"})
    try:
        result = run_query(data.query)
        return {"result": result}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
