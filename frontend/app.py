"""
TrustVault - Enterprise Secure Document Sharing Platform.
Streamlit Frontend Application.
"""

import os
import io
import httpx
import streamlit as st

# Styling helper
try:
    from frontend.styles import CUSTOM_CSS, get_role_badge_html
except ImportError:
    from styles import CUSTOM_CSS, get_role_badge_html


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------
st.set_page_config(
    page_title="TrustVault - Secure Document Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

API_URL = os.getenv(
    "API_URL",
    "https://trustvault-api-c2oq.onrender.com"
).rstrip("/")


# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------
if "token" not in st.session_state:
    st.session_state.token = None

if "user" not in st.session_state:
    st.session_state.user = None


# ---------------------------------------------------------
# API HELPERS
# ---------------------------------------------------------
def get_headers():
    if st.session_state.token:
        return {
            "Authorization": f"Bearer {st.session_state.token}"
        }
    return {}


def api_request(method, endpoint, **kwargs):
    """Send requests to the FastAPI backend."""

    headers = kwargs.pop("headers", {})
    headers.update(get_headers())

    url = f"{API_URL}{endpoint}"

    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.request(
                method,
                url,
                headers=headers,
                **kwargs
            )
            return response

    except httpx.TimeoutException:
        st.error(
            "The backend took too long to respond. "
            "Please wait and try again."
        )
        return None

    except httpx.ConnectError:
        st.error(
            f"Could not connect to the backend: {API_URL}. "
            "Please check whether the backend is running."
        )
        return None

    except Exception as e:
        st.error(f"Network error: {str(e)}")
        return None


def safe_json(response, default=None):
    """Decode JSON safely without crashing Streamlit."""

    if default is None:
        default = {}

    if response is None:
        return default

    try:
        return response.json()
    except (ValueError, TypeError):
        return default


def get_error_detail(response, fallback="Request failed"):
    """Extract an error message even if the backend returns HTML."""

    if response is None:
        return "No response received from backend."

    data = safe_json(response)

    if isinstance(data, dict):
        return str(data.get("detail", fallback))

    if isinstance(data, str) and data:
        return data

    body = (response.text or "").strip()

    if body:
        return (
            f"HTTP {response.status_code}: "
            f"{body[:500]}"
        )

    return f"{fallback} (HTTP {response.status_code})"


def format_bytes(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"

    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"

    return f"{size_bytes / (1024 * 1024):.2f} MB"


def logout():
    st.session_state.token = None
    st.session_state.user = None
    st.rerun()


def complete_login(response):
    """Store authenticated user details."""

    data = safe_json(response)

    required_fields = [
        "access_token",
        "user_id",
        "name",
        "email",
        "role"
    ]

    if not isinstance(data, dict):
        st.error("Invalid response received from backend.")
        return False

    if not all(field in data for field in required_fields):
        st.error("Backend login response is missing required fields.")
        return False

    st.session_state.token = data["access_token"]

    st.session_state.user = {
        "id": data["user_id"],
        "name": data["name"],
        "email": data["email"],
        "role": data["role"]
    }

    return True


# ---------------------------------------------------------
# AUTHENTICATION SCREEN
# ---------------------------------------------------------
if not st.session_state.token:

    st.markdown(
        """
        <div style="text-align:center;margin-top:2rem;margin-bottom:2rem;">
            <h1 style="font-size:2.75rem;font-weight:800;color:#0f172a;">
                🔒 TrustVault
            </h1>
            <p style="font-size:1.15rem;color:#64748b;">
                Secure Document-Sharing Platform with
                Tamper-Evident SHA-256 Audit Logging
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:

        tab_login, tab_register, tab_quick_demo = st.tabs(
            [
                "🔑 Sign In",
                "📝 Register",
                "⚡ Quick Demo Login"
            ]
        )

        # -------------------------------------------------
        # LOGIN
        # -------------------------------------------------
        with tab_login:

            st.subheader("Login to your Vault")

            login_email = st.text_input(
                "Email Address",
                key="login_email"
            )

            login_password = st.text_input(
                "Password",
                type="password",
                key="login_pwd"
            )

            if st.button(
                "Sign In",
                type="primary",
                use_container_width=True
            ):

                if not login_email or not login_password:
                    st.warning("Please enter your email and password.")

                else:

                    with st.spinner("Authenticating..."):

                        res = api_request(
                            "POST",
                            "/auth/login",
                            json={
                                "email": login_email.strip(),
                                "password": login_password
                            }
                        )

                    if res is None:
                        st.error("Unable to connect to the backend.")

                    elif res.status_code == 200:

                        if complete_login(res):
                            st.success(
                                f"Welcome back, "
                                f"{st.session_state.user['name']}!"
                            )
                            st.rerun()

                    else:
                        st.error(
                            f"Login failed: "
                            f"{get_error_detail(res, 'Authentication failed')}"
                        )

        # -------------------------------------------------
        # REGISTRATION
        # -------------------------------------------------
        with tab_register:

            st.subheader("Create a New Account")

            reg_name = st.text_input(
                "Full Name",
                key="reg_name"
            )

            reg_email = st.text_input(
                "Email Address",
                key="reg_email"
            )

            reg_password = st.text_input(
                "Password (min 8 characters)",
                type="password",
                key="reg_pwd"
            )

            # Public registration cannot assign admin privileges.
            reg_role = st.selectbox(
                "Requested Role",
                ["viewer", "owner"],
                help=(
                    "Viewer: view and download shared documents. "
                    "Owner: upload and share documents."
                )
            )

            if st.button(
                "Register Account",
                type="primary",
                use_container_width=True
            ):

                if not reg_name.strip() or not reg_email.strip() or not reg_password:
                    st.warning("All fields are required.")

                elif len(reg_password) < 8:
                    st.warning(
                        "Password must contain at least 8 characters."
                    )

                else:

                    payload = {
                        "name": reg_name.strip(),
                        "email": reg_email.strip(),
                        "password": reg_password,
                        "role": reg_role
                    }

                    with st.spinner("Creating your account..."):

                        res = api_request(
                            "POST",
                            "/auth/register",
                            json=payload
                        )

                    if res is None:

                        st.error(
                            "Could not connect to the backend. "
                            "Please try again."
                        )

                    elif res.status_code == 201:

                        st.success(
                            "Account registered successfully! "
                            "Please log in from the Sign In tab."
                        )

                    else:

                        detail = get_error_detail(
                            res,
                            "Registration failed"
                        )

                        st.error(
                            f"Registration failed: {detail}"
                        )

        # -------------------------------------------------
        # QUICK DEMO LOGIN
        # -------------------------------------------------
        with tab_quick_demo:

            st.subheader("One-Click Evaluator Login")

            st.info(
                "Use these demo accounts if they have been "
                "created in your backend database."
            )

            c_admin, c_owner, c_viewer = st.columns(3)

            demo_accounts = [
                (
                    c_admin,
                    "👑 Admin Role",
                    "admin@trustvault.com",
                    "TrustVaultAdmin2026!"
                ),
                (
                    c_owner,
                    "📁 Owner Role",
                    "owner@trustvault.com",
                    "TrustVaultOwner2026!"
                ),
                (
                    c_viewer,
                    "👁️ Viewer Role",
                    "viewer@trustvault.com",
                    "TrustVaultViewer2026!"
                )
            ]

            for column, label, email, password in demo_accounts:

                with column:

                    if st.button(
                        label,
                        use_container_width=True
                    ):

                        with st.spinner("Logging in..."):

                            res = api_request(
                                "POST",
                                "/auth/login",
                                json={
                                    "email": email,
                                    "password": password
                                }
                            )

                        if res is None:
                            st.error("Backend connection failed.")

                        elif res.status_code == 200:

                            if complete_login(res):
                                st.rerun()

                        else:
                            st.error(
                                get_error_detail(
                                    res,
                                    "Demo login failed"
                                )
                            )

    st.stop()


# ---------------------------------------------------------
# AUTHENTICATED USER
# ---------------------------------------------------------
user = st.session_state.user

if not user:
    logout()

role_badge = get_role_badge_html(user["role"])


# ---------------------------------------------------------
# BRAND HEADER
# ---------------------------------------------------------
st.markdown(
    f"""
    <div class="brand-header">
        <div>
            <div class="brand-title">🔒 TrustVault</div>
            <div class="brand-subtitle">
                Logged in as <b>{user['name']}</b>
                ({user['email']})
                &bull; Role: {role_badge}
            </div>
        </div>
        <div>
            <span style="font-size:0.85rem;color:#94a3b8;">
                JWT Authenticated
            </span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# SIDEBAR NAVIGATION
# ---------------------------------------------------------
with st.sidebar:

    st.image(
        "https://img.icons8.com/fluency/96/lock-shield.png",
        width=64
    )

    st.markdown(f"### **{user['name']}**")

    st.markdown(
        f"**Role:** {get_role_badge_html(user['role'])}",
        unsafe_allow_html=True
    )

    st.markdown(f"**Email:** `{user['email']}`")

    st.divider()

    nav_options = [
        "📊 Dashboard Overview",
        "📂 Document Vault",
        "⬆️ Secure Upload",
        "🤝 Collaborator & Sharing",
        "🛡️ Tamper-Evident Audit Logs"
    ]

    if user["role"] == "admin":
        nav_options.append("👥 User Management")

    active_page = st.radio(
        "Navigation",
        nav_options
    )

    st.divider()

    # Backend health
    health_res = api_request("GET", "/health")

    if health_res and health_res.status_code == 200:

        h = safe_json(health_res)

        st.caption(f"Backend API: 🟢 {h.get('api', 'Connected')}")
        st.caption(f"Database: 🟢 {h.get('database', 'Connected')}")
        st.caption(f"Storage: 🟢 {h.get('storage', 'Available')}")
        st.caption(f"Hash Chain: 🟢 {h.get('audit_chain', 'Available')}")

    else:
        st.caption("Backend Status: 🔴 Disconnected")

    st.divider()

    if st.button(
        "🚪 Sign Out",
        use_container_width=True
    ):
        logout()


# ---------------------------------------------------------
# PAGE 1: DASHBOARD OVERVIEW
# ---------------------------------------------------------
if active_page == "📊 Dashboard Overview":

    st.header("Security & Vault Dashboard")

    docs_res = api_request("GET", "/documents")

    docs = (
        safe_json(docs_res, [])
        if docs_res and docs_res.status_code == 200
        else []
    )

    audit_verify_res = api_request(
        "GET",
        "/audit/verify"
    )

    is_chain_valid = False
    chain_details = "Not verified"
    total_logs = 0

    if audit_verify_res and audit_verify_res.status_code == 200:

        v_data = safe_json(audit_verify_res)

        is_chain_valid = v_data.get("is_valid", False)
        chain_details = v_data.get("details", "")
        total_logs = v_data.get("total_records", 0)

    m1, m2, m3, m4 = st.columns(4)

    total_storage = sum(
        d.get("size_bytes", 0) for d in docs
    )

    with m1:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{len(docs)}</div>
                <div class="metric-label">Accessible Documents</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with m2:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{format_bytes(total_storage)}</div>
                <div class="metric-label">Vault Storage Used</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with m3:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{total_logs}</div>
                <div class="metric-label">Chained Audit Events</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with m4:

        status_text = "VALID" if is_chain_valid else "TAMPERED"
        status_color = "#16a34a" if is_chain_valid else "#dc2626"

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value" style="color:{status_color};">
                    {status_text}
                </div>
                <div class="metric-label">SHA-256 Hash Chain</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    if is_chain_valid:

        st.markdown(
            f"""
            <div class="security-status-valid">
                <h4 style="margin:0 0 0.5rem 0;color:#065f46;">
                    🛡️ Cryptographic Integrity Confirmed
                </h4>
                <p style="margin:0;font-size:0.95rem;">
                    {chain_details}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="security-status-invalid">
                <h4 style="margin:0 0 0.5rem 0;color:#991b1b;">
                    ⚠️ Audit Chain Not Verified
                </h4>
                <p style="margin:0;font-size:0.95rem;">
                    {chain_details}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader("Platform Security Architecture")

    f1, f2, f3 = st.columns(3)

    with f1:
        st.info(
            "**🔐 Password Security & JWT**\n\n"
            "- Argon2id password hashing\n"
            "- Cryptographically signed HS256 tokens\n"
            "- Role-Based Access Control"
        )

    with f2:
        st.info(
            "**📦 Secure Storage**\n\n"
            "- Files stored outside web root\n"
            "- SHA-256 integrity checks\n"
            "- 10MB maximum file size"
        )

    with f3:
        st.info(
            "**⛓️ Tamper-Evident Chaining**\n\n"
            "- SHA-256 cryptographic hash chaining\n"
            "- Audit records of security events\n"
            "- Detection of unauthorized alterations"
        )


# ---------------------------------------------------------
# PAGE 2: DOCUMENT VAULT
# ---------------------------------------------------------
elif active_page == "📂 Document Vault":

    st.header("Document Vault")

    c_search, c_cat, c_scope = st.columns([2, 1, 1])

    with c_search:
        search_query = st.text_input(
            "🔍 Search documents by filename...",
            key="vault_search"
        )

    with c_cat:

        category_filter = st.selectbox(
            "Category Filter",
            [
                "All Categories",
                "Confidential",
                "Finance",
                "Legal",
                "Technical",
                "HR",
                "Other"
            ]
        )

    with c_scope:

        scope_options = [
            "All Accessible",
            "My Uploads",
            "Shared with Me"
        ]

        selected_scope = st.selectbox(
            "View Scope",
            scope_options
        )

    scope_param = "all"

    if selected_scope == "My Uploads":
        scope_param = "owned"

    elif selected_scope == "Shared with Me":
        scope_param = "shared"

    params = {"scope": scope_param}

    if search_query:
        params["query"] = search_query

    if category_filter != "All Categories":
        params["category"] = category_filter

    with st.spinner("Loading documents..."):

        res = api_request(
            "GET",
            "/documents",
            params=params
        )

    if res and res.status_code == 200:

        docs = safe_json(res, [])

        if not docs:

            st.info(
                "No documents match your query or view criteria."
            )

        else:

            st.write(
                f"Showing **{len(docs)}** document(s):"
            )

            for doc in docs:

                with st.expander(
                    f"📄 **{doc['original_filename']}** | "
                    f"{doc.get('category') or 'Uncategorized'} | "
                    f"{format_bytes(doc['size_bytes'])}",
                    expanded=True
                ):

                    col_info, col_actions = st.columns([3, 2])

                    with col_info:

                        st.markdown(
                            f"**Owner:** {doc['owner_name']} "
                            f"(`{doc['owner_email']}`)"
                        )

                        st.markdown(
                            f"**Uploaded:** "
                            f"`{doc['created_at'][:19].replace('T', ' ')}`"
                        )

                        st.markdown(
                            f"**Effective Permission:** "
                            f"`{doc['effective_permission'].upper()}`"
                        )

                        st.markdown(
                            f"**SHA-256 Checksum:** "
                            f"`{doc['checksum_sha256']}`"
                        )

                    with col_actions:

                        # Download
                        dl_res = api_request(
                            "GET",
                            f"/documents/{doc['id']}/download"
                        )

                        if dl_res and dl_res.status_code == 200:

                            st.download_button(
                                label="⬇️ Download Verified File",
                                data=dl_res.content,
                                file_name=doc["original_filename"],
                                mime=doc.get(
                                    "content_type",
                                    "application/octet-stream"
                                ),
                                key=f"dl_{doc['id']}",
                                use_container_width=True
                            )

                        elif dl_res:

                            st.error(
                                "Download unavailable: "
                                f"{get_error_detail(dl_res)}"
                            )

                        # Edit metadata
                        if doc["effective_permission"] in (
                            "owner",
                            "admin",
                            "edit"
                        ):

                            with st.popover(
                                "✏️ Edit Metadata",
                                use_container_width=True
                            ):

                                new_name = st.text_input(
                                    "Filename",
                                    value=doc["original_filename"],
                                    key=f"name_{doc['id']}"
                                )

                                new_cat = st.text_input(
                                    "Category",
                                    value=doc.get("category") or "",
                                    key=f"cat_{doc['id']}"
                                )

                                if st.button(
                                    "Save Changes",
                                    key=f"save_{doc['id']}",
                                    type="primary"
                                ):

                                    up_res = api_request(
                                        "PUT",
                                        f"/documents/{doc['id']}",
                                        json={
                                            "original_filename": new_name,
                                            "category": new_cat
                                        }
                                    )

                                    if up_res and up_res.status_code == 200:

                                        st.success("Metadata updated!")
                                        st.rerun()

                                    else:

                                        st.error(
                                            get_error_detail(
                                                up_res,
                                                "Failed to update metadata"
                                            )
                                        )

                        # Delete
                        if doc["effective_permission"] in (
                            "owner",
                            "admin"
                        ):

                            with st.popover(
                                "🗑️ Delete",
                                use_container_width=True
                            ):

                                st.warning(
                                    f"Are you sure you want to delete "
                                    f"'{doc['original_filename']}'?"
                                )

                                if st.button(
                                    "Confirm Delete",
                                    key=f"del_{doc['id']}",
                                    type="primary"
                                ):

                                    del_res = api_request(
                                        "DELETE",
                                        f"/documents/{doc['id']}"
                                    )

                                    if del_res and del_res.status_code == 200:

                                        st.success("Document deleted.")
                                        st.rerun()

                                    else:

                                        st.error(
                                            get_error_detail(
                                                del_res,
                                                "Delete failed"
                                            )
                                        )

    elif res:

        st.error(
            get_error_detail(
                res,
                "Unable to load documents"
            )
        )


# ---------------------------------------------------------
# PAGE 3: SECURE DOCUMENT UPLOAD
# ---------------------------------------------------------
elif active_page == "⬆️ Secure Upload":

    st.header("Secure Document Upload")

    if user["role"] not in ("admin", "owner"):

        st.warning(
            "🔒 **Viewer Role Restriction:**\n\n"
            "Your account has the Viewer role. "
            "Only Owner or Admin accounts can upload documents."
        )

    else:

        st.markdown(
            "Upload files up to **10MB**. Files are verified "
            "with SHA-256 and stored in private storage."
        )

        with st.form(
            "upload_form",
            clear_on_submit=True
        ):

            uploaded_file = st.file_uploader(
                "Choose a file to securely store",
                type=None
            )

            category_choice = st.selectbox(
                "Category",
                [
                    "Confidential",
                    "Finance",
                    "Legal",
                    "Technical",
                    "HR",
                    "General",
                    "Other"
                ]
            )

            custom_category = st.text_input(
                "Or enter custom category tag (optional)"
            )

            submit = st.form_submit_button(
                "🔒 Upload & Encrypt",
                type="primary",
                use_container_width=True
            )

            if submit:

                if uploaded_file is None:

                    st.warning("Please choose a file to upload.")

                else:

                    file_bytes = uploaded_file.getvalue()
                    file_size = len(file_bytes)

                    if file_size > 10 * 1024 * 1024:

                        st.error(
                            "File exceeds maximum allowed size of 10MB."
                        )

                    elif file_size == 0:

                        st.error("Cannot upload an empty file.")

                    else:

                        cat = (
                            custom_category.strip()
                            if custom_category.strip()
                            else category_choice
                        )

                        files = {
                            "file": (
                                uploaded_file.name,
                                io.BytesIO(file_bytes),
                                uploaded_file.type
                                or "application/octet-stream"
                            )
                        }

                        data = {
                            "category": cat
                        }

                        with st.spinner(
                            "Uploading and computing SHA-256 checksum..."
                        ):

                            up_res = api_request(
                                "POST",
                                "/documents/upload",
                                files=files,
                                data=data
                            )

                        if up_res and up_res.status_code == 201:

                            doc_data = safe_json(up_res)

                            st.success(
                                f"Document "
                                f"'{doc_data.get('original_filename', uploaded_file.name)}' "
                                f"successfully stored!"
                            )

                            st.markdown(
                                f"""
                                **Upload Summary:**

                                - **Document ID:** `{doc_data.get('id', 'N/A')}`
                                - **Size:** `{format_bytes(doc_data.get('size_bytes', file_size))}`
                                - **Registered SHA-256:** `{doc_data.get('checksum_sha256', 'N/A')}`
                                - **Tamper-Evident Audit Event:** Recorded
                                """
                            )

                        elif up_res:

                            st.error(
                                f"Upload error: "
                                f"{get_error_detail(up_res, 'Upload failed')}"
                            )


# ---------------------------------------------------------
# PAGE 4: COLLABORATOR & SHARING
# ---------------------------------------------------------
elif active_page == "🤝 Collaborator & Sharing":

    st.header("Document Access & Sharing Control")

    docs_res = api_request(
        "GET",
        "/documents",
        params={"scope": "owned"}
    )

    owned_docs = (
        safe_json(docs_res, [])
        if docs_res and docs_res.status_code == 200
        else []
    )

    if user["role"] == "admin":

        all_docs_res = api_request(
            "GET",
            "/documents",
            params={"scope": "all"}
        )

        owned_docs = (
            safe_json(all_docs_res, [])
            if all_docs_res and all_docs_res.status_code == 200
            else []
        )

    if not owned_docs:

        st.info(
            "You do not have any owned documents available to share. "
            "Upload a document first!"
        )

    else:

        doc_options = {
            f"{d['original_filename']} (ID: {d['id']})": d
            for d in owned_docs
        }

        selected_label = st.selectbox(
            "Select Document to Manage Permissions",
            list(doc_options.keys())
        )

        selected_doc = doc_options[selected_label]

        col_grant, col_list = st.columns([1, 1])

        # Grant access
        with col_grant:

            st.subheader("Grant Access")

            share_email = st.text_input(
                "Recipient Email Address",
                placeholder="user@trustvault.com"
            )

            access_level = st.radio(
                "Access Level",
                ["read", "edit"],
                format_func=lambda x: (
                    "👁️ Read-Only (View & Download)"
                    if x == "read"
                    else "✏️ Edit (View, Download, & Modify)"
                )
            )

            if st.button(
                "Grant Permission",
                type="primary",
                use_container_width=True
            ):

                if not share_email.strip():

                    st.warning("Please enter recipient email.")

                else:

                    with st.spinner("Granting permission..."):

                        p_res = api_request(
                            "POST",
                            f"/documents/{selected_doc['id']}/permissions",
                            json={
                                "user_email": share_email.strip(),
                                "access_level": access_level
                            }
                        )

                    if p_res and p_res.status_code == 201:

                        st.success(
                            f"Granted '{access_level}' access "
                            f"to {share_email}!"
                        )

                        st.rerun()

                    elif p_res:

                        st.error(
                            get_error_detail(
                                p_res,
                                "Failed to grant permission"
                            )
                        )

        # Current collaborators
        with col_list:

            st.subheader("Current Collaborators")

            with st.spinner("Loading permissions..."):

                perms_res = api_request(
                    "GET",
                    f"/documents/{selected_doc['id']}/permissions"
                )

            if perms_res and perms_res.status_code == 200:

                perms = safe_json(perms_res, [])

                if not perms:

                    st.caption(
                        "No collaborators currently have access."
                    )

                else:

                    for p in perms:

                        c_user, c_btn = st.columns([3, 1])

                        with c_user:

                            st.markdown(
                                f"**{p['user_name']}** "
                                f"(`{p['user_email']}`)<br>"
                                f"Permission: `{p['access_level'].upper()}` "
                                f"&bull; Granted by: `{p['granted_by_name']}`",
                                unsafe_allow_html=True
                            )

                        with c_btn:

                            if st.button(
                                "❌ Revoke",
                                key=f"rev_{p['id']}"
                            ):

                                rev_res = api_request(
                                    "DELETE",
                                    f"/documents/{selected_doc['id']}"
                                    f"/permissions/{p['user_id']}"
                                )

                                if rev_res and rev_res.status_code == 200:

                                    st.success("Access revoked!")
                                    st.rerun()

                                else:

                                    st.error(
                                        get_error_detail(
                                            rev_res,
                                            "Failed to revoke access"
                                        )
                                    )

                        st.divider()

            elif perms_res:

                st.error(
                    get_error_detail(
                        perms_res,
                        "Unable to load permissions"
                    )
                )


# ---------------------------------------------------------
# PAGE 5: TAMPER-EVIDENT AUDIT LOGS
# ---------------------------------------------------------
elif active_page == "🛡️ Tamper-Evident Audit Logs":

    st.header("Cryptographic Audit Trail")

    st.markdown(
        "TrustVault logs document access, uploads, downloads, "
        "modifications, permissions, and denied access attempts. "
        "Each record is cryptographically bound to its predecessor "
        "using **SHA-256 hash chaining**."
    )

    col_v1, col_v2 = st.columns([1, 2])

    with col_v1:

        verify_clicked = st.button(
            "🔍 Verify Hash Chain Integrity",
            type="primary",
            use_container_width=True
        )

    with col_v2:

        if (
            verify_clicked
            or "last_verify" not in st.session_state
        ):

            with st.spinner(
                "Verifying SHA-256 hash chain..."
            ):

                v_res = api_request(
                    "GET",
                    "/audit/verify"
                )

                if v_res and v_res.status_code == 200:

                    st.session_state.last_verify = safe_json(v_res)

                elif v_res:

                    st.error(
                        get_error_detail(
                            v_res,
                            "Hash verification failed"
                        )
                    )

        v = st.session_state.get(
            "last_verify",
            {}
        )

        if v.get("is_valid"):

            st.success(
                f"✅ **Chain Intact:** {v.get('details', '')}"
            )

        elif v:

            st.error(
                f"❌ **Integrity Alert:** {v.get('details', '')}"
            )

        else:

            st.info("Hash chain has not been verified yet.")

    st.divider()

    f_action = st.selectbox(
        "Filter by Action Type",
        [
            "All Actions",
            "UPLOAD",
            "DOWNLOAD",
            "EDIT",
            "DELETE",
            "PERMISSION_GRANT",
            "PERMISSION_REVOKE",
            "ACCESS_DENIED",
            "LOGIN_SUCCESS",
            "LOGIN_FAILED",
            "USER_REGISTER"
        ]
    )

    params = {
        "limit": 100
    }

    if f_action != "All Actions":
        params["action"] = f_action

    with st.spinner("Loading audit logs..."):

        logs_res = api_request(
            "GET",
            "/audit/logs",
            params=params
        )

    if logs_res and logs_res.status_code == 200:

        logs = safe_json(logs_res, [])

        if not logs:

            st.info(
                "No audit logs found for the selected filter."
            )

        else:

            table_data = []

            for log in logs:

                table_data.append(
                    {
                        "ID": log["id"],
                        "Timestamp": log["created_at"][:19].replace("T", " "),
                        "Action": log["action"],
                        "Actor": (
                            f"{log['actor_name']} "
                            f"({log['actor_email']})"
                            if log.get("actor_email")
                            else "System / Anonymous"
                        ),
                        "Target Doc": log.get("document_filename") or "N/A",
                        "Client IP": log.get("ip_address") or "127.0.0.1",
                        "Details": log.get("details", ""),
                        "Entry SHA-256": (
                            f"{log['entry_hash'][:16]}..."
                        )
                    }
                )

            st.dataframe(
                table_data,
                use_container_width=True
            )

    elif logs_res:

        st.error(
            get_error_detail(
                logs_res,
                "Unable to load audit logs"
            )
        )


# ---------------------------------------------------------
# PAGE 6: ADMIN USER MANAGEMENT
# ---------------------------------------------------------
elif (
    active_page == "👥 User Management"
    and user["role"] == "admin"
):

    st.header("Admin User Management")

    with st.spinner("Loading users..."):

        users_res = api_request(
            "GET",
            "/users"
        )

    if users_res and users_res.status_code == 200:

        all_users = safe_json(users_res, [])

        st.write(
            f"Total Registered Users: **{len(all_users)}**"
        )

        for u in all_users:

            with st.container(border=True):

                cu1, cu2, cu3 = st.columns([3, 2, 2])

                with cu1:

                    st.markdown(f"**{u['name']}**")
                    st.markdown(f"Email: `{u['email']}`")

                    st.caption(
                        f"Registered: {u['created_at'][:10]}"
                    )

                with cu2:

                    current_role = u["role"]

                    roles = [
                        "admin",
                        "owner",
                        "viewer"
                    ]

                    new_role = st.selectbox(
                        "Role",
                        roles,
                        index=roles.index(current_role),
                        key=f"role_{u['id']}"
                    )

                    if new_role != current_role:

                        if st.button(
                            "Update Role",
                            key=f"btn_role_{u['id']}"
                        ):

                            r_res = api_request(
                                "PATCH",
                                f"/users/{u['id']}/role",
                                json={
                                    "role": new_role
                                }
                            )

                            if r_res and r_res.status_code == 200:

                                st.success(
                                    f"Updated {u['email']} "
                                    f"to {new_role}!"
                                )

                                st.rerun()

                            elif r_res:

                                st.error(
                                    get_error_detail(
                                        r_res,
                                        "Role update failed"
                                    )
                                )

                with cu3:

                    is_active = u["is_active"]

                    status_label = (
                        "🟢 Active"
                        if is_active
                        else "🔴 Deactivated"
                    )

                    st.markdown(
                        f"Status: **{status_label}**"
                    )

                    if u["id"] != user["id"]:

                        toggle_text = (
                            "Deactivate"
                            if is_active
                            else "Activate"
                        )

                        if st.button(
                            toggle_text,
                            key=f"btn_status_{u['id']}"
                        ):

                            s_res = api_request(
                                "PATCH",
                                f"/users/{u['id']}/status",
                                json={
                                    "is_active": not is_active
                                }
                            )

                            if s_res and s_res.status_code == 200:

                                st.success(
                                    f"Updated status for {u['email']}!"
                                )

                                st.rerun()

                            elif s_res:

                                st.error(
                                    get_error_detail(
                                        s_res,
                                        "Status update failed"
                                    )
                                )

    elif users_res:

        st.error(
            get_error_detail(
                users_res,
                "Unable to load users"
            )
        )