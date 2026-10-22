import os
import uvicorn


if __name__ == "__main__":
    port = int(os.getenv("PANEL_PORT", "8443"))
    cert = os.getenv("PANEL_SSL_CERT") or None
    key = os.getenv("PANEL_SSL_KEY") or None
    uvicorn.run("app.main:app", host="0.0.0.0", port=port,
                ssl_certfile=cert, ssl_keyfile=key, proxy_headers=False,
                server_header=False, access_log=False, workers=1)
