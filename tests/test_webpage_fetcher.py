
import sys
from pathlib import Path

# Add the project root to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.webpage_fetcher import fetch_webpage


# Test website
url = "https://example.com"

try:
    result = fetch_webpage(url)

    print("=" * 50)
    print("COMPPHISH WEBPAGE FETCH TEST")
    print("=" * 50)

    print("Final URL:", result["final_url"])
    print("Content type:", result["content_type"])
    print("HTML length:", len(result["html"]))

    print("\nHTML preview:")
    print(result["html"][:500])

    print("\nWEBPAGE FETCH SUCCESSFUL")

except Exception as exc:
    print("\nFETCH FAILED:", exc)
