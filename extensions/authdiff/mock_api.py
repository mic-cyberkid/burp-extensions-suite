from flask import Flask, jsonify, request

app = Flask(__name__)

def get_user_context():
    # Identify user based on authorization headers or cookies
    auth_header = request.headers.get("Authorization", "")
    tenant_header = request.headers.get("X-Tenant-ID", "")
    session_cookie = request.cookies.get("session_id", "")

    if "TOKEN_USER_C" in auth_header or tenant_header == "tenant_003" or session_cookie == "sess_user_c":
        return "User C"
    elif "TOKEN_USER_B" in auth_header or tenant_header == "tenant_002" or session_cookie == "sess_user_b":
        return "User B"
    else:
        return "User A"  # default to admin / high privilege original traffic

@app.route('/api/v1/public/health', methods=['GET'])
def public_health():
    return jsonify({
        "status": "healthy",
        "timestamp": "2023-10-27T12:00:00Z",
        "version": "1.0.0"
    }), 200

@app.route('/api/v1/user/profile', methods=['GET'])
def user_profile():
    user = get_user_context()
    if user == "User A":
        return jsonify({
            "username": "admin_user_a",
            "role": "Administrator",
            "tenant": "tenant_001",
            "email": "admin@targetapp.com"
        }), 200
    else:
        # Correctly enforces RBAC
        return jsonify({
            "error": "Forbidden",
            "message": "Access denied. Requires Administrator role."
        }), 403

@app.route('/api/v1/documents/doc_1001', methods=['GET'])
def vulnerable_doc():
    # Vulnerable IDOR: returns same sensitive data to anyone!
    # Does not check if the user belongs to tenant_001 or owns doc_1001.
    return jsonify({
        "document_id": "doc_1001",
        "owner": "admin_user_a",
        "tenant_id": "tenant_001",
        "title": "Q3 Financial Plan & Secrets",
        "content": "IDOR vulnerabilities are extremely dangerous.",
        "confidentiality": "STRICTLY PRIVATE"
    }), 200

@app.route('/api/v1/admin/delete', methods=['POST'])
def vulnerable_delete():
    user = get_user_context()
    # Vulnerable BAC: allows low-privilege User B/C to execute admin deletion!
    return jsonify({
        "status": "success",
        "action": "delete_all_logs",
        "requested_by": user,
        "message": f"Database logs have been permanently deleted by {user}."
    }), 200

if __name__ == '__main__':
    # Run the Flask app on localhost:5000
    app.run(host='127.0.0.1', port=5000)
