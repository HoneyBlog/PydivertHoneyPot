from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from handlers import main_loop_handler, asset_handler, all_packet_handler

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def catch_all(request: Request, path: str):
    # Forward the request to the appropriate handler based on the path
    if path.startswith("api/assets"):
        return await asset_handler(request)
    elif path.startswith("api/packets"):
        return await all_packet_handler(request)
    else:
        return await main_loop_handler(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000, reload=True)