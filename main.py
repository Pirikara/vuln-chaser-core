from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import logging
from datetime import datetime
import uuid
import json

# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VulnChaser Core",
    description="LLM-powered vulnerability analysis engine for IAST",
    version="0.1.0"
)

# CORS configuration for Ruby agent communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for PoC
analysis_results: Dict[str, Any] = {}
trace_batches: Dict[str, Any] = {}

# Data models
class TraceData(BaseModel):
    trace_id: str
    request_info: Dict[str, Any]
    execution_trace: List[Dict[str, Any]]

class TraceBatchData(BaseModel):
    batch_id: str
    timestamp: str
    traces: List[TraceData]

class VulnerabilityResult(BaseModel):
    owasp_category: str
    type: str
    severity: str
    confidence: float
    affected_method: str
    line: int
    description: str
    recommendation: str

class BatchAnalysisResponse(BaseModel):
    batch_id: str
    results: List[Dict[str, Any]]
    analysis_time_ms: int
    cost_usd: float

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0"
    }

@app.post("/api/traces/batch", response_model=BatchAnalysisResponse)
async def analyze_trace_batch(batch_data: TraceBatchData):
    """
    Receive and analyze a batch of traces from Ruby agent
    """
    try:
        logger.info(f"Received batch {batch_data.batch_id} with {len(batch_data.traces)} traces")
        
        # Store batch for reference
        trace_batches[batch_data.batch_id] = batch_data.dict()
        
        # Initialize vulnerability analyzer
        from services.vulnerability_analyzer import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()
        
        # Convert traces to dict format for analysis
        traces_for_analysis = [trace.dict() for trace in batch_data.traces]
        
        # Perform LLM-based vulnerability analysis
        results = await analyzer.analyze_batch(traces_for_analysis)
        
        # Store results
        analysis_results[batch_data.batch_id] = results
        
        # Calculate total metrics
        total_time = sum(r.get("analysis_metadata", {}).get("response_time_ms", 0) for r in results)
        total_cost = sum(r.get("analysis_metadata", {}).get("cost_usd", 0.0) for r in results)
        
        response = BatchAnalysisResponse(
            batch_id=batch_data.batch_id,
            results=results,
            analysis_time_ms=total_time,
            cost_usd=total_cost
        )
        
        # Log vulnerability findings
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        if total_vulns > 0:
            logger.warning(f"Batch {batch_data.batch_id}: Found {total_vulns} vulnerabilities!")
        else:
            logger.info(f"Batch {batch_data.batch_id}: No vulnerabilities detected")
        
        logger.info(f"Completed analysis for batch {batch_data.batch_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing batch {batch_data.batch_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/results/{batch_id}")
async def get_batch_results(batch_id: str):
    """Get analysis results for a specific batch"""
    if batch_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return {
        "batch_id": batch_id,
        "results": analysis_results[batch_id],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    total_vulns = 0
    for results in analysis_results.values():
        total_vulns += sum(len(r.get("vulnerabilities", [])) for r in results)
    
    return {
        "total_batches": len(trace_batches),
        "total_results": len(analysis_results),
        "total_vulnerabilities": total_vulns,
        "memory_usage_mb": 0,
        "uptime": "placeholder"
    }

@app.get("/report", response_class=HTMLResponse)
async def vulnerability_report():
    """HTML vulnerability report dashboard"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnChaser Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            .header { text-align: center; color: #333; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
            .stats { display: flex; justify-content: space-around; margin: 20px 0; }
            .stat-box { background: #3498db; color: white; padding: 20px; border-radius: 5px; text-align: center; }
            .vulnerability { background: #fff; border-left: 4px solid #e74c3c; margin: 10px 0; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .vulnerability.high { border-color: #c0392b; }
            .vulnerability.medium { border-color: #f39c12; }
            .vulnerability.low { border-color: #f1c40f; }
            .vulnerability.critical { border-color: #8e44ad; }
            .batch { margin: 20px 0; padding: 15px; background: #ecf0f1; border-radius: 5px; }
            .no-data { text-align: center; color: #7f8c8d; padding: 40px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ VulnChaser Security Report</h1>
                <p>Generated at """ + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC") + """</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>""" + str(len(trace_batches)) + """</h3>
                    <p>Total Batches</p>
                </div>
                <div class="stat-box">
                    <h3>""" + str(sum(len(r.get("vulnerabilities", [])) for results in analysis_results.values() for r in results)) + """</h3>
                    <p>Vulnerabilities Found</p>
                </div>
                <div class="stat-box">
                    <h3>""" + str(len(analysis_results)) + """</h3>
                    <p>Analyzed Batches</p>
                </div>
            </div>
            
            <h2>🚨 Vulnerability Details</h2>
    """
    
    if not analysis_results:
        html_content += '<div class="no-data">No vulnerability analysis results yet. Send some requests to your application to see vulnerabilities detected!</div>'
    else:
        for batch_id, results in analysis_results.items():
            html_content += f'<div class="batch"><h3>Batch: {batch_id}</h3>'
            
            has_vulns = False
            for result in results:
                vulnerabilities = result.get("vulnerabilities", [])
                if vulnerabilities:
                    has_vulns = True
                    trace_id = result.get("trace_id", "Unknown")
                    html_content += f'<h4>Trace: {trace_id}</h4>'
                    
                    for vuln in vulnerabilities:
                        severity = vuln.get("severity", "unknown").lower()
                        html_content += f'''
                        <div class="vulnerability {severity}">
                            <h4>{vuln.get("type", "Unknown Vulnerability")}</h4>
                            <p><strong>Severity:</strong> {vuln.get("severity", "Unknown").upper()}</p>
                            <p><strong>Confidence:</strong> {vuln.get("confidence", 0):.1%}</p>
                            <p><strong>OWASP Category:</strong> {vuln.get("owasp_category", "Unknown")}</p>
                            <p><strong>Affected Method:</strong> {vuln.get("affected_method", "Unknown")}</p>
                            <p><strong>Description:</strong> {vuln.get("description", "No description available")}</p>
                            <p><strong>Recommendation:</strong> {vuln.get("recommendation", "No recommendation available")}</p>
                        </div>
                        '''
            
            if not has_vulns:
                html_content += '<p style="color: green;">✅ No vulnerabilities detected in this batch</p>'
            
            html_content += '</div>'
    
    html_content += """
            </div>
        </body>
    </html>
    """
    
    return html_content

@app.get("/api/vulnerabilities")
async def get_all_vulnerabilities():
    """Get all vulnerabilities in JSON format"""
    all_vulnerabilities = []
    
    for batch_id, results in analysis_results.items():
        for result in results:
            vulnerabilities = result.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                vuln_data = vuln.copy()
                vuln_data["batch_id"] = batch_id
                vuln_data["trace_id"] = result.get("trace_id", "Unknown")
                all_vulnerabilities.append(vuln_data)
    
    return {
        "total_vulnerabilities": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=True,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )