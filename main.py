from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import logging
from datetime import datetime

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
    # Pattern-Free fields (new format)
    vulnerability_classification: Optional[str] = None
    severity: str
    confidence: float
    affected_component: Optional[str] = None
    creative_description: Optional[str] = None
    attack_scenario: Optional[str] = None
    business_impact: Optional[str] = None
    novel_aspects: Optional[str] = None
    remediation_strategy: Optional[str] = None
    sor_relationship: Optional[str] = None
    
    # Legacy fields (backward compatibility)
    owasp_category: Optional[str] = None
    type: Optional[str] = None
    affected_method: Optional[str] = None
    line: Optional[int] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None

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
        
        batch_dict = batch_data.dict()
        
        # Store batch for reference
        trace_batches[batch_data.batch_id] = batch_dict
        
        # Initialize vulnerability analyzer
        from services.vulnerability_analyzer import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()
        
        # Use SOR-enabled analyze_batch method with trace_batch format
        results = await analyzer.analyze_batch(batch_dict)
        
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

@app.get("/api/cache/stats")
async def get_cache_stats():
    """Get analysis cache statistics to monitor deduplication effectiveness"""
    try:
        from services.vulnerability_analyzer import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()
        
        cache_stats = analyzer.get_cache_stats()
        sor_metrics = analyzer.get_sor_performance_metrics()
        
        return {
            "cache_statistics": cache_stats,
            "sor_performance": sor_metrics,
            "deduplication_effectiveness": {
                "requests_saved": cache_stats.get('cache_hits', 0),
                "cost_saved_usd": cache_stats.get('cache_hits', 0) * 0.01,  # Estimated cost per request
                "response_time_saved_ms": cache_stats.get('cache_hits', 0) * 2000  # Estimated 2s per LLM call
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting cache stats: {str(e)}")
        return {
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.post("/api/cache/clear")
async def clear_cache():
    """Clear the analysis cache"""
    try:
        from services.vulnerability_analyzer import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()
        
        analyzer.clear_analysis_cache()
        
        return {
            "message": "Analysis cache cleared successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error clearing cache: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

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
            .vulnerability { background: #fff; border-left: 4px solid #e74c3c; margin: 10px 0; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 5px; }
            .vulnerability.high { border-color: #c0392b; }
            .vulnerability.medium { border-color: #f39c12; }
            .vulnerability.low { border-color: #f1c40f; }
            .vulnerability.critical { border-color: #8e44ad; background: #fdf2f8; }
            .vulnerability h4 { color: #2c3e50; margin-top: 0; }
            .vulnerability p { margin: 8px 0; line-height: 1.4; }
            .vulnerability strong { color: #34495e; }
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
                        
                        # Support both old and new field formats
                        classification = vuln.get("vulnerability_classification", vuln.get("type", "Unknown Vulnerability"))
                        description = vuln.get("creative_description", vuln.get("description", "No description available"))
                        affected_component = vuln.get("affected_component", vuln.get("affected_method", "Unknown"))
                        remediation = vuln.get("remediation_strategy", vuln.get("recommendation", "No recommendation available"))
                        attack_scenario = vuln.get("attack_scenario", "")
                        business_impact = vuln.get("business_impact", "")
                        novel_aspects = vuln.get("novel_aspects", "")
                        
                        html_content += f'''
                        <div class="vulnerability {severity}">
                            <h4>{classification}</h4>
                            <p><strong>Severity:</strong> {vuln.get("severity", "Unknown").upper()}</p>
                            <p><strong>Confidence:</strong> {vuln.get("confidence", 0):.1%}</p>
                            <p><strong>Affected Component:</strong> {affected_component}</p>
                            <p><strong>Description:</strong> {description}</p>'''
                        
                        if attack_scenario:
                            html_content += f'<p><strong>Attack Scenario:</strong> {attack_scenario}</p>'
                        
                        if business_impact:
                            html_content += f'<p><strong>Business Impact:</strong> {business_impact}</p>'
                        
                        if novel_aspects:
                            html_content += f'<p><strong>Novel Aspects:</strong> {novel_aspects}</p>'
                            
                        html_content += f'<p><strong>Remediation Strategy:</strong> {remediation}</p>'
                        
                        # Add SOR context if available
                        if vuln.get("sor_relationship"):
                            html_content += f'<p><strong>SOR Relationship:</strong> {vuln["sor_relationship"]}</p>'
                        
                        # Add Pattern-Free analysis context
                        if vuln.get("vuln_chaser_context"):
                            context = vuln["vuln_chaser_context"]
                            if context.get("pattern_free_analysis"):
                                pf_analysis = context["pattern_free_analysis"]
                                if pf_analysis.get("creative_risk_assessment", {}).get("novel_risks_identified"):
                                    html_content += f'<p><strong>Pattern-Free Analysis:</strong> {pf_analysis["creative_risk_assessment"]["novel_risks_identified"][:200]}...</p>'
                        
                        html_content += '</div>'
            
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