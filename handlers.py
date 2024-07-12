from fastapi import Request, HTTPException
import httpx
import logging

BACKEND_URL = "http://localhost:8000"  # URL for the regular backend
HONEYPOT_BACKEND_URL = "http://localhost:8001"  # URL for the honeypot backend

logger = logging.getLogger("uvicorn.error")

async def forward_request(request: Request, backend_url: str):
    try:
        request_data = await request.body()
        headers = dict(request.headers)
        headers["Referer"] = "http://localhost:9000"
        headers["Origin"] = "http://localhost:9000"
        headers.pop("host", None)  # Remove host to avoid conflicts
        logger.info(f"Forwarding request to {backend_url}{request.url.path} with method {request.method} and data: {request_data}")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.request(
                method=request.method,
                url=f"{backend_url}{request.url.path}",
                headers=headers,
                content=request_data,
                timeout=10.0
            )
        logger.info(f"Received response: {response.status_code} - {response.text}")
        return response
    except httpx.RequestError as exc:
        logger.error(f"An error occurred while requesting {exc.request.url!r}: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}: {exc}")
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.TimeoutException:
        logger.error(f"Request to {backend_url} timed out.")
        raise HTTPException(status_code=504, detail="Request timed out")

async def main_loop_handler(request: Request):
    response = await forward_request(request, BACKEND_URL)
    return response.json()

async def asset_handler(request: Request):
    response = await forward_request(request, HONEYPOT_BACKEND_URL)
    return response.json()

async def all_packet_handler(request: Request):
    response = await forward_request(request, HONEYPOT_BACKEND_URL)
    return response.json()
