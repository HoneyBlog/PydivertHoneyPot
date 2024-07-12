import threading
import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
import pydivert
import queue
import httpx
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("uvicorn.error")

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Queue to hold packets for processing
packet_queue = queue.Queue()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    client_host = request.client.host
    client_port = request.client.port
    referer = request.headers.get('referer', 'None')
    origin = request.headers.get('origin', 'None')

    logger.info(f"Incoming request from {client_host}:{client_port}, Referer: {referer}, Origin: {origin}")

    response = await call_next(request)
    return response

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def catch_all(request: Request, path: str):
    logger.info(f"Catch-all route received request for path: {path}")
    return await forward_request(request, "http://127.0.0.1:8000")

def main_loop():
    with pydivert.WinDivert("tcp.DstPort == 9000") as w:
        for packet in w:
            if packet.tcp.syn or packet.tcp.fin:
                # Send back SYN-ACK or FIN-ACK
                packet.tcp.ack = True
                w.send(packet)
            elif packet.payload:
                # Modify the destination port to 8000 before forwarding
                original_dst_port = packet.dst_port
                packet.dst_port = 8000
                packet.recalculate_checksums()
                packet_queue.put(packet)
                w.send(packet)
                logger.info(f"Packet intercepted and modified: {packet} original_dst_port: {original_dst_port}")

def packet_processor():
    while True:
        packet = packet_queue.get()
        if packet:
            # For this example, simply log the packet details
            logger.info(f"Processed packet with src_port={packet.src_port}, dst_port={packet.dst_port}, data={packet.payload}")
            packet_queue.task_done()

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
        logger.info(f"Received response from {backend_url}: {response.status_code} - {response.text}")
        return JSONResponse(status_code=response.status_code, content=response.json())
    except httpx.RequestError as exc:
        logger.error(f"An error occurred while requesting {exc.request.url!r}: {exc}")
        logger.error(f"Exception details: {exc}")
        raise HTTPException(status_code=500, detail="Internal server error")
    except httpx.HTTPStatusError as exc:
        logger.error(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}: {exc}")
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except httpx.TimeoutException:
        logger.error(f"Request to {backend_url} timed out.")
        raise HTTPException(status_code=504, detail="Request timed out")

if __name__ == "__main__":
    threading.Thread(target=main_loop).start()
    threading.Thread(target=packet_processor).start()
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000, reload=True)