from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from modules.header_inspector import HeaderInspector
from modules.form_auditor import FormAuditor
from modules.banner_logger import BannerLogger
from utils.helpers import validate_url, sanitize_url

app = FastAPI(title="Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target_url: str

@app.post("/api/scan")
def scan_target(req: ScanRequest):
    url = sanitize_url(req.target_url)
    if not validate_url(url):
        raise HTTPException(status_code=400, detail="Invalid target URL")

    config = {
        'target': {'url': url, 'follow_redirects': True, 'max_redirects': 5, 'timeout': 10, 'verify_ssl': False},
        'headers': {'enabled': True, 'checks': [
            'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Referrer-Policy', 'X-XSS-Protection'
        ]},
        'forms': {'enabled': True, 'csrf_field_names': [
            '_token', 'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token'
        ]},
        'ports': {'enabled': True, 'timeout': 5, 'list': [
            80, 443, 8080, 8443, 3306, 5432, 6379, 22, 21
        ]}
    }

    results = {
        "target_url": url,
        "headers": {},
        "forms": [],
        "banners": []
    }

    # Run Header Inspector
    try:
        inspector = HeaderInspector(config)
        results["headers"] = inspector.run()
        html_content = inspector.get_response_text()
    except Exception as e:
        html_content = None
        results["headers_error"] = str(e)

    # Run Form Auditor
    if html_content:
        try:
            auditor = FormAuditor(config)
            results["forms"] = auditor.run(html_content)
        except Exception as e:
            results["forms_error"] = str(e)

    # Run Banner Logger
    try:
        banner_logger = BannerLogger(config)
        results["banners"] = banner_logger.run()
    except Exception as e:
        results["banners_error"] = str(e)

    return results

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
