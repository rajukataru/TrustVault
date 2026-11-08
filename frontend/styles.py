"""Custom styling and CSS components for TrustVault Streamlit frontend."""

CUSTOM_CSS = """
<style>
    /* Global Styles */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* App Header / Brand */
    .brand-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        color: #f8fafc;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .brand-title {
        font-size: 1.8rem;
        font-weight: 700;
        letter-spacing: -0.025em;
        margin: 0;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .brand-subtitle {
        font-size: 0.9rem;
        color: #94a3b8;
        margin-top: 0.25rem;
    }

    /* Role Badges */
    .role-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .role-admin {
        background-color: #fee2e2;
        color: #991b1b;
        border: 1px solid #fecaca;
    }

    .role-owner {
        background-color: #dcfce7;
        color: #166534;
        border: 1px solid #bbf7d0;
    }

    .role-viewer {
        background-color: #e0f2fe;
        color: #075985;
        border: 1px solid #bae6fd;
    }

    /* Metric Cards */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 1.25rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        text-align: center;
    }

    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #0f172a;
    }

    .metric-label {
        font-size: 0.825rem;
        font-weight: 500;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.25rem;
    }

    /* Security Status Card */
    .security-status-valid {
        background: #ecfdf5;
        border: 1px solid #10b981;
        border-radius: 10px;
        padding: 1rem 1.5rem;
        color: #065f46;
        margin-bottom: 1.5rem;
    }

    .security-status-invalid {
        background: #fef2f2;
        border: 1px solid #ef4444;
        border-radius: 10px;
        padding: 1rem 1.5rem;
        color: #991b1b;
        margin-bottom: 1.5rem;
    }

    /* Quick Demo Login Box */
    .demo-login-box {
        background: #f8fafc;
        border: 1px dashed #cbd5e1;
        border-radius: 10px;
        padding: 1.25rem;
        margin-top: 1rem;
    }
</style>
"""


def get_role_badge_html(role: str) -> str:
    """Generates styled HTML role badge."""
    r = role.lower()
    return f'<span class="role-badge role-{r}">{role}</span>'
