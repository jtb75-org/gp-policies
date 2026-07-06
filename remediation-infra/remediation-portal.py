import os
import sqlite3
import json
import requests
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
import uvicorn

app = FastAPI()

DB_FILE = "/data/remediations.db"
API_KEY_NAME = "X-Webhook-Token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Wiz API Credentials (passed to the container via env vars)
WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL", "https://api.us.wiz.io/graphql")
WIZ_AUTH_URL = os.getenv("WIZ_AUTH_URL", "https://auth.wiz.io/oauth/token")
PORTAL_TOKEN = os.getenv("PORTAL_TOKEN", "super-secret-token")

# =============================================================================
# Database Setup
# =============================================================================
def init_db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            bucket TEXT,
            file_name TEXT,
            file_external_id TEXT,
            platform TEXT,
            status TEXT,
            detected_at TEXT,
            raw_payload TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# =============================================================================
# Authentication
# =============================================================================
def verify_token(api_key: str = Depends(api_key_header)):
    if not api_key or api_key != PORTAL_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )
    return api_key

# =============================================================================
# Wiz API Integration (Placeholder)
# =============================================================================
def get_wiz_token():
    """Authenticate to Wiz and get a bearer token."""
    if not WIZ_CLIENT_ID or not WIZ_CLIENT_SECRET:
        print("Warning: WIZ_CLIENT_ID or WIZ_CLIENT_SECRET not set. Cannot authenticate to Wiz.")
        return None
        
    payload = {
        "grant_type": "client_credentials",
        "audience": "https://api.wiz.io",
        "client_id": WIZ_CLIENT_ID,
        "client_secret": WIZ_CLIENT_SECRET
    }
    try:
        response = requests.post(WIZ_AUTH_URL, data=payload)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        print(f"Failed to get Wiz token: {e}")
        return None

def trigger_wiz_remediation(resource_id: str, action_catalog_item_id: str):
    """Call the Wiz GraphQL API to trigger the response action on the resource.
    
    TODO: Replace the placeholder mutation with the actual mutation name and variables
    once discovered from the Wiz API Explorer or Network tab.
    """
    token = get_wiz_token()
    if not token:
        raise Exception("Failed to authenticate to Wiz API")

    # PLACEHOLDER MUTATION
    query = """
    mutation RunResponseAction($input: RunResponseActionInput!) {
        runResponseAction(input: $input) {
            remediationTaskId
            status
        }
    }
    """
    
    variables = {
        "input": {
            "responseActionCatalogItemId": action_catalog_item_id,
            "resourceId": resource_id
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    print(f"Sending mutation to Wiz API for resource {resource_id}...")
    try:
        response = requests.post(
            WIZ_API_URL,
            json={"query": query, "variables": variables},
            headers=headers
        )
        response.raise_for_status()
        result = response.json()
        
        if "errors" in result:
            raise Exception(f"Wiz API returned errors: {result['errors']}")
            
        print(f"Wiz API response: {result}")
        return result.get("data", {}).get("runResponseAction", {})
    except Exception as e:
        print(f"Failed to trigger Wiz remediation: {e}")
        raise e

# =============================================================================
# API Endpoints
# =============================================================================

@app.post("/webhook")
async def receive_webhook(request: Request, _ = Depends(verify_token)):
    """Receives the webhook from Wiz Workflow."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract data from the Wiz TDR Workflow payload
    file_external_id = payload.get("file_external_id")
    bucket = payload.get("bucket")
    file_name = payload.get("file_name", "Unknown File")
    platform = payload.get("platform") or payload.get("cloud") or "AWS"
    
    if not file_external_id or not bucket:
        raise HTTPException(status_code=400, detail="Missing required fields: file_external_id or bucket")

    finding_id = file_external_id

    conn = get_db_conn()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO findings (id, bucket, file_name, file_external_id, platform, status, detected_at, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
        """, (finding_id, bucket, file_name, file_external_id, platform, "PENDING", json.dumps(payload)))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    conn.close()

    print(f"Received and stored finding: {file_name} in {bucket} ({platform})")
    return {"status": "stored", "id": finding_id}


@app.get("/api/findings")
def list_findings(_ = Depends(verify_token)):
    """Lists all findings in the DB."""
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, bucket, file_name, file_external_id, platform, status, detected_at FROM findings ORDER BY detected_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(finding_id: str, _ = Depends(verify_token)):
    """Approve remediation: Triggers the Wiz Response Action based on platform."""
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding = dict(row)
    if finding["status"] != "PENDING":
        conn.close()
        raise HTTPException(status_code=400, detail=f"Finding is already {finding['status']}")

    # Select the correct Action Catalog Item ID based on the platform
    platform = finding["platform"].upper()
    if platform == "AWS":
        action_catalog_item_id = os.getenv("WIZ_ACTION_AWS_ID")
    elif platform == "GCP":
        action_catalog_item_id = os.getenv("WIZ_ACTION_GCP_ID")
    elif platform == "AZURE":
        action_catalog_item_id = os.getenv("WIZ_ACTION_AZURE_ID")
    else:
         action_catalog_item_id = None

    if not action_catalog_item_id:
        conn.close()
        raise HTTPException(
            status_code=500, 
            detail=f"WIZ_ACTION_{platform}_ID environment variable not set for platform {platform}"
        )

    try:
        # TRIGGER WIZ REMEDIATION
        trigger_wiz_remediation(finding["file_external_id"], action_catalog_item_id)
        
        # Update status in DB
        cursor.execute("UPDATE findings SET status = 'APPROVED' WHERE id = ?", (finding_id,))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to trigger remediation: {str(e)}")
        
    conn.close()
    return {"status": "approved", "detail": f"Remediation triggered via Wiz API for {platform}"}


@app.post("/api/findings/{finding_id}/reject")
def reject_finding(finding_id: str, _ = Depends(verify_token)):
    """Reject remediation: Just mark as ignored."""
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding = dict(row)
    if finding["status"] != "PENDING":
        conn.close()
        raise HTTPException(status_code=400, detail=f"Finding is already {finding['status']}")

    cursor.execute("UPDATE findings SET status = 'REJECTED' WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()
    return {"status": "rejected"}

# =============================================================================
# Frontend UI (Single Page App)
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def get_index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Wiz Remediation Approval Portal</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }
            h1 { color: #1e293b; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
            .login-box { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); text-align: center; }
            input[type="password"] { width: 100%; padding: 10px; margin: 15px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { background-color: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; }
            button:hover { background-color: #2563eb; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
            th { background-color: #f8fafc; color: #64748b; }
            .badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
            .badge-pending { background-color: #fef3c7; color: #d97706; }
            .badge-approved { background-color: #dcfce7; color: #15803d; }
            .badge-rejected { background-color: #fee2e2; color: #b91c1c; }
            .badge-platform { background-color: #e2e8f0; color: #475569; }
            .btn-approve { background-color: #10b981; margin-right: 5px; }
            .btn-approve:hover { background-color: #059669; }
            .btn-reject { background-color: #ef4444; }
            .btn-reject:hover { background-color: #dc2626; }
            .hidden { display: none; }
        </style>
    </head>
    <body>
        <div id="login-page" class="login-box">
            <h2>Remediation Portal Login</h2>
            <p>Enter your Portal Token to access the dashboard</p>
            <input type="password" id="token-input" placeholder="Enter Token">
            <button onclick="login()">Login</button>
        </div>

        <div id="dashboard-page" class="container hidden">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h1>Wiz Remediation Approval Portal</h1>
                <button onclick="logout()" style="background-color: #64748b;">Logout</button>
            </div>
            <p>Review and approve pending malware quarantines.</p>
            
            <table id="findings-table">
                <thead>
                    <tr>
                        <th>Detected At</th>
                        <th>Platform</th>
                        <th>Bucket/Target</th>
                        <th>File Name</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="findings-body">
                    <!-- Loaded dynamically -->
                </tbody>
            </table>
        </div>

        <script>
            let token = localStorage.getItem("portal_token") || "";

            function showPage() {
                if (token) {
                    document.getElementById("login-page").classList.add("hidden");
                    document.getElementById("dashboard-page").classList.remove("hidden");
                    loadFindings();
                } else {
                    document.getElementById("login-page").classList.remove("hidden");
                    document.getElementById("dashboard-page").classList.add("hidden");
                }
            }

            function login() {
                const input = document.getElementById("token-input").value;
                if (input) {
                    token = input;
                    localStorage.setItem("portal_token", token);
                    showPage();
                }
            }

            function logout() {
                token = "";
                localStorage.removeItem("portal_token");
                showPage();
            }

            async function fetchAPI(path, options = {}) {
                if (!options.headers) options.headers = {};
                options.headers["X-Webhook-Token"] = token;
                
                const response = await fetch(path, options);
                if (response.status === 401) {
                    logout();
                    return null;
                }
                return response;
            }

            async function loadFindings() {
                const response = await fetchAPI("/api/findings");
                if (!response) return;
                const findings = await response.json();
                
                const body = document.getElementById("findings-body");
                body.innerHTML = "";
                
                if (findings.length === 0) {
                    body.innerHTML = "<tr><td colspan='6' style='text-align:center;'>No findings recorded yet.</td></tr>";
                    return;
                }

                findings.forEach(f => {
                    const tr = document.createElement("tr");
                    
                    let actionButtons = "";
                    if (f.status === "PENDING") {
                        actionButtons = `
                            <button class="btn-approve" onclick="actionFinding('${f.id}', 'approve')">Quarantine</button>
                            <button class="btn-reject" onclick="actionFinding('${f.id}', 'reject')">Ignore</button>
                        `;
                    } else {
                        actionButtons = `<span style="color: #94a3b8;">No actions available</span>`;
                    }

                    tr.innerHTML = `
                        <td>${f.detected_at}</td>
                        <td><span class="badge badge-platform">${f.platform}</span></td>
                        <td>${f.bucket}</td>
                        <td>${f.file_name}</td>
                        <td><span class="badge badge-${f.status.toLowerCase()}">${f.status}</span></td>
                        <td>${actionButtons}</td>
                    `;
                    body.appendChild(tr);
                });
            }

            async function actionFinding(id, action) {
                if (!confirm(`Are you sure you want to ${action} this remediation?`)) return;
                
                const response = await fetchAPI(`/api/findings/${id}/${action}`, { method: "POST" });
                if (response && response.ok) {
                    alert(`Successfully triggered ${action} action.`);
                    loadFindings();
                } else {
                    const err = await response.json();
                    alert(`Error: ${err.detail || 'Action failed'}`);
                }
            }

            // Init
            showPage();
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
