from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import os
import subprocess
import json
from jose import jwt, JWTError
from db import get_connection, parse_json_field, rows_to_dicts
from scanner.checks.ssl_check import check_ssl
from scanner.checks.headers_check import check_headers
from scanner.checks.phi_check import check_phi
from scanner.scorer import calculate_score

router = APIRouter()
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

class DeployRequest(BaseModel):
    repo_url: str
    branch: str = "main"

def get_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("")
def deploy(req: DeployRequest, authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    user_id = get_user(token)

    conn = get_connection()
    cur = conn.cursor()

    # Save deployment record as running
    cur.execute(
        "INSERT INTO deployments (user_id, repo_url, branch, status) VALUES (?, ?, ?, 'running')",
        (user_id, req.repo_url, req.branch)
    )
    conn.commit()
    deploy_id = cur.lastrowid

    # Run HIPAA checks against the repo URL as a website
    try:
        findings = []
        findings += check_ssl(req.repo_url)
        findings += check_headers(req.repo_url)
        findings += check_phi(req.repo_url)

        failed = [f for f in findings if not f["passed"] and f["severity"] == "critical"]
        status = "failed" if failed else "passed"
        score, rating = calculate_score(findings)

        test_results = {
            "score": score,
            "rating": rating,
            "total_checks": len(findings),
            "failed_checks": failed
        }

        cur.execute(
            "UPDATE deployments SET status=?, test_results=? WHERE id=?",
            (status, json.dumps(test_results), deploy_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        return {
            "deploy_id": deploy_id,
            "status": status,
            "score": score,
            "rating": rating,
            "failed_checks": failed,
            "deploy_url": req.repo_url if status == "passed" else None
        }

    except Exception as e:
        cur.execute("UPDATE deployments SET status='failed' WHERE id=?", (deploy_id,))
        conn.commit()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
def deploy_history(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    user_id = get_user(token)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, repo_url, branch, status, test_results, created_at FROM deployments WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (user_id,)
    )
    deployments = rows_to_dicts(cur.fetchall())
    for deployment in deployments:
        deployment["test_results"] = parse_json_field(deployment.get("test_results"))
    cur.close()
    conn.close()
    return {"deployments": deployments}
