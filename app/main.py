from fastapi import FastAPI, HTTPException
from typing import List, Dict
import uvicorn
from database import Database
from cloud_providers.aws_analyzer import AWSSecurityAnalyzer
from cloud_providers.azure_analyzer import AzureSecurityAnalyzer
from models.security_findings import SecurityFinding
from models.compliance import ComplianceCheck

app = FastAPI(title="Cloud Security Posture Management API")
db = Database()

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/analyze/aws")
async def analyze_aws_security(account_id: str):
    try:
        analyzer = AWSSecurityAnalyzer(account_id)
        findings = await analyzer.run_security_assessment()
        return {"findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/azure")
async def analyze_azure_security(subscription_id: str):
    try:
        analyzer = AzureSecurityAnalyzer(subscription_id)
        findings = await analyzer.run_security_assessment()
        return {"findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)