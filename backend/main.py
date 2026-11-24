
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.prediction_service import predict_website
from backend.webpage_fetcher import fetch_webpage


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

        from backend.prediction_service import MODEL

        return {
            "status": "ok",
            "model_loaded": MODEL is not None,
            "model_name": MODEL.get("model_name"),
            "threshold": MODEL.get("threshold"),
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

        # C. Return scan results

        return {
            "success": True,

            "model": "CompPhish Hybrid Multi-Modal Model",

            "submitted_url": request.url,

            "final_url": webpage["final_url"],

            "content_type": webpage["content_type"],

            "html_size": len(html),

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
