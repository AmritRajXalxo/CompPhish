
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.prediction_service import predict_website
from backend.webpage_fetcher import fetch_webpage
from backend import reports_store
from backend.brand_check import brand_check
from backend.scan_intel import (
    network_footprint,
    page_behaviour,
    server_location,
    threat_feeds,
    tls_details,
)
from backend.trust_signals import assess_trust
from backend.verdict import compose_verdict


# --------------------------------------------------
# 1. FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="CompPhish API",
    description="Hybrid Multi-Modal Phishing Detection System",
    version="1.1.0",
)
@app.get("/healthz")
def health_check():
    return {"status": "healthy"}

# --------------------------------------------------
# 2. CORS configuration
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------
# 3. Request schemas
# --------------------------------------------------

class WebsiteRequest(BaseModel):

    url: str = Field(
        ...,
        min_length=1,
        description="Website URL",
    )

    html: str = Field(
        ...,
        min_length=1,
        description="HTML source of the webpage",
    )


class ScanRequest(BaseModel):

    url: str = Field(
        ...,
        min_length=1,
        description="Website URL to scan",
    )

    include_preview: bool = Field(
        False,
        description="Add a third-party screenshot link (thum.io) to the response",
    )


class ReportRequest(BaseModel):

    url: str = Field(..., min_length=1, max_length=2000)
    category: str = Field(..., description="scam, safe or other")
    comment: str = Field("", max_length=300)


# --------------------------------------------------
# 4. Root endpoint
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "name": "CompPhish API",
        "status": "running",
        "version": "1.1.0",
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "scan": "/scan",
            "documentation": "/docs",
        },
    }


# --------------------------------------------------
# 5. Health endpoint
# --------------------------------------------------

@app.get("/health")
def health():

    try:

        from backend import prediction_service as ps
        MODEL = ps.MODEL

        return {
            "status": "ok",
            "model_loaded": MODEL is not None,
            "model_name": MODEL.get("model_name"),
            "threshold": MODEL.get("threshold"),
            "bands": {
                "legitimate_below": ps.LOW_THRESHOLD,
                "phishing_at_or_above": ps.HIGH_THRESHOLD,
            },
        }

    except Exception as exc:

        raise HTTPException(
            status_code=503,
            detail=f"Model unavailable: {exc}",
        )


# --------------------------------------------------
# 6. Existing prediction endpoint
# --------------------------------------------------

@app.post("/predict")
def predict(request: WebsiteRequest):

    """
    Accepts URL and HTML supplied by the caller.
    """

    try:

        result = predict_website(
            url=request.url,
            html=request.html,
        )

        return {
            "success": True,
            "model": "CompPhish Hybrid Multi-Modal Model",
            **result,
        }

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {exc}",
        )


# --------------------------------------------------
# 7. New automatic website scanning endpoint
# --------------------------------------------------

@app.post("/scan")
def scan_website(request: ScanRequest):

    """
    Accepts a website URL, retrieves its HTML,
    and performs hybrid phishing detection.
    """

    try:

        # A. Retrieve webpage HTML

        webpage = fetch_webpage(request.url)

        html = webpage["html"]

        # B. Run the complete hybrid prediction pipeline

        result = predict_website(
            url=request.url,
            html=html,
        )

        # C. Gather independent evidence in parallel

        final_url = webpage["final_url"]
        host = (urlparse(final_url).hostname or "").lower()

        with ThreadPoolExecutor(max_workers=6) as pool:
            f_trust = pool.submit(assess_trust, request.url, final_url)
            f_tls = pool.submit(tls_details, host)
            f_feeds = pool.submit(threat_feeds, final_url)
            f_loc = pool.submit(server_location, host)
            f_net = pool.submit(network_footprint, html, final_url)
            behaviour = page_behaviour(html, final_url)
            trust, tls = f_trust.result(), f_tls.result()
            feeds, location, footprint = (
                f_feeds.result(), f_loc.result(), f_net.result()
            )

        result["redirect_chain"] = webpage.get("redirect_chain", [])
        result = compose_verdict(
            result, trust, feeds, behaviour, tls, brand_check(final_url)
        )

        # D. Return scan results

        return {
            "success": True,

            "model": "CompPhish Hybrid Multi-Modal Model",

            "submitted_url": request.url,

            "final_url": webpage["final_url"],

            "content_type": webpage["content_type"],

            "html_size": len(html),

            "tls": tls,
            "threat_feeds": feeds,
            "page_behaviour": behaviour,
            "network_footprint": footprint,
            "server_location": location,
            "statistics": {
                "load_seconds": webpage.get("load_seconds"),
                "status_code": webpage.get("status_code"),
                "html_bytes": len(html),
                "cookies_set": webpage.get("cookie_count"),
                "security_headers": webpage.get("security_headers"),
                "server_header": webpage.get("server_header"),
            },
            "community_reports": reports_store.summary(final_url),
            "preview_url": (
                f"https://image.thum.io/get/width/900/noanimate/{final_url}"
                if request.include_preview else None
            ),

            **result,
        }

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Website scanning failed: {exc}",
        )



# --------------------------------------------------
# 8. Community reports
# --------------------------------------------------

@app.post("/report")
def report_link(request: ReportRequest, http_request: Request):

    client = http_request.client.host if http_request.client else "unknown"

    try:
        return {
            "success": True,
            "community_reports": reports_store.add_report(
                request.url, request.category, request.comment, client
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=429, detail=str(exc))


@app.get("/reports")
def get_reports(url: str):

    return reports_store.summary(url)
