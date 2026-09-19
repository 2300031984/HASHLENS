"""
HashLens Dashboard
Security Operations Center (SOC) style web interface for file integrity,
chunk forensics, version timelines, tamper-evident chaining, and evidence reporting.
"""

import streamlit as st
from dashboard.utils.styles import apply_soc_theme
from dashboard.utils.api_client import api_client

st.set_page_config(
    page_title="HashLens | File Integrity & Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_soc_theme()

# Initialize session state for authentication
if "auth_token" not in st.session_state:
    st.session_state["auth_token"] = None
if "current_user" not in st.session_state:
    st.session_state["current_user"] = None
if "auth_mode" not in st.session_state:
    st.session_state["auth_mode"] = "login"

# Sync client token with session state
if st.session_state["auth_token"]:
    api_client.auth_token = st.session_state["auth_token"]


def render_auth_screen():
    """Renders SOC-themed authentication interface when user is not logged in."""
    st.markdown(
        """
        <div style="text-align: center; margin-top: 10px; margin-bottom: 25px;">
            <h1 style="color: #00f0ff; font-weight: 800; letter-spacing: 0.15em; margin-bottom: 0;">HASHLENS</h1>
            <div style="font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.15em;">
                Secure File Integrity & Hash Forensics Platform
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        auth_choice = st.radio(
            "ACCOUNT ACCESS",
            ["Login", "Create Account"],
            index=0 if st.session_state["auth_mode"] == "login" else 1,
            horizontal=True,
            key="auth_tab_radio",
        )

        if auth_choice == "Login":
            st.session_state["auth_mode"] = "login"
            st.markdown(
                """
                <div class="soc-card" style="padding: 20px; margin-top: 10px;">
                    <h3 style="color: #00f0ff; margin-top: 0; font-size: 18px;">HASHLENS Authentication</h3>
                    <p style="color: #94a3b8; font-size: 12px; margin-bottom: 15px;">Secure File Integrity & Hash Forensics</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.form("login_form"):
                login_id = st.text_input("Email / Username", key="login_id_field")
                password = st.text_input("Password", type="password", key="login_pwd_field")
                submit_login = st.form_submit_button("Login", use_container_width=True)

                if submit_login:
                    if not login_id or not password:
                        st.error("Please enter both your Email / Username and Password.")
                    else:
                        res = api_client.login(login_id, password)
                        if "error" in res:
                            st.error(res["error"])
                        else:
                            st.session_state["auth_token"] = res["access_token"]
                            st.session_state["current_user"] = res["user"]
                            api_client.auth_token = res["access_token"]
                            st.success(f"Welcome, {res['user']['username']}!")
                            st.rerun()

            st.markdown("Don't have an account?")
            if st.button("Create account", key="btn_goto_register"):
                st.session_state["auth_mode"] = "register"
                st.rerun()

        else:
            st.session_state["auth_mode"] = "register"
            st.markdown(
                """
                <div class="soc-card" style="padding: 20px; margin-top: 10px;">
                    <h3 style="color: #00f0ff; margin-top: 0; font-size: 18px;">HASHLENS Registration</h3>
                    <p style="color: #94a3b8; font-size: 12px; margin-bottom: 15px;">Create your account</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.form("register_form"):
                reg_email = st.text_input("Email", key="reg_email_field")
                reg_username = st.text_input("Username", key="reg_username_field")
                reg_password = st.text_input("Password", type="password", key="reg_pwd_field")
                reg_confirm_pwd = st.text_input("Confirm Password", type="password", key="reg_confirm_pwd_field")
                submit_reg = st.form_submit_button("Create Account", use_container_width=True)

                if submit_reg:
                    if not reg_email or not reg_username or not reg_password:
                        st.error("Please fill in all required registration fields.")
                    elif reg_password != reg_confirm_pwd:
                        st.error("Passwords do not match.")
                    elif len(reg_password) < 8:
                        st.error("Password must be at least 8 characters long.")
                    else:
                        res = api_client.register(reg_email, reg_username, reg_password)
                        if "error" in res:
                            st.error(res["error"])
                        else:
                            st.success("Account created successfully! Authenticating...")
                            login_res = api_client.login(reg_email, reg_password)
                            if "access_token" in login_res:
                                st.session_state["auth_token"] = login_res["access_token"]
                                st.session_state["current_user"] = login_res["user"]
                                api_client.auth_token = login_res["access_token"]
                                st.rerun()
                            else:
                                st.session_state["auth_mode"] = "login"
                                st.rerun()

            st.markdown("Already have an account?")
            if st.button("Login", key="btn_goto_login"):
                st.session_state["auth_mode"] = "login"
                st.rerun()


# Sidebar Header & Quick Status
st.sidebar.markdown(
    """
    <div style="text-align: center; padding: 10px 0 20px 0;">
        <h2 style="color: #00f0ff; margin-bottom: 2px; font-weight: 800; letter-spacing: 0.1em;">HASHLENS</h2>
        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.15em;">
            File Integrity & Forensics Platform
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Live Chain Heartbeat in Sidebar
health = api_client.get_health()
chain_badge = "badge-green" if health.get("chain_health") == "CHAIN_VALID" else "badge-yellow"
if health.get("chain_health") == "CHAIN_BROKEN":
    chain_badge = "badge-red"

st.sidebar.markdown(
    f"""
    <div class="soc-card" style="padding: 12px; margin-bottom: 20px;">
        <div class="stat-label">PLATFORM STATUS</div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">
            <span style="font-size: 13px; font-weight: 600;">{health.get('status', 'ONLINE').upper()}</span>
            <span class="badge-tag {chain_badge}">{health.get('chain_health', 'CHAIN_VALID')}</span>
        </div>
        <div style="font-size: 11px; color: #64748b; margin-top: 6px;">
            v{health.get('version', '1.0.0')} | Env: {health.get('environment', 'dev')}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Show login UI if user is not authenticated
if not st.session_state["current_user"]:
    render_auth_screen()
else:
    # Sidebar Authenticated User Card
    user = st.session_state["current_user"]
    st.sidebar.markdown(
        f"""
        <div class="soc-card" style="padding: 10px; margin-bottom: 15px; border-left: 3px solid #00f0ff;">
            <div class="stat-label">AUTHENTICATED USER</div>
            <div style="font-size: 13px; font-weight: 700; color: #f8fafc; margin-top: 4px;">👤 {user.get('username')}</div>
            <div style="font-size: 11px; color: #94a3b8;">{user.get('email')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.sidebar.button("🔓 Logout", use_container_width=True):
        api_client.logout()
        st.session_state["auth_token"] = None
        st.session_state["current_user"] = None
        st.session_state["auth_mode"] = "login"
        st.rerun()

    # Navigation Menu
    nav_choice = st.sidebar.radio(
        "NAVIGATION",
        [
            "1. Overview",
            "2. Hash Generator",
            "3. File Integrity",
            "4. Compare Files",
            "5. Version Timeline",
            "6. Integrity Chain",
            "7. Evidence Reports",
            "8. Security Guide",
            "9. API Information",
        ],
        index=0,
    )

    st.sidebar.markdown("---")
    st.sidebar.caption("HashLens Forensics Platform • Python 3.11 • FastAPI • SQLite/PostgreSQL")

    # Route to Page View
    if nav_choice == "1. Overview":
        from dashboard.pages_impl import overview_view
        overview_view.render()
    elif nav_choice == "2. Hash Generator":
        from dashboard.pages_impl import hash_generator_view
        hash_generator_view.render()
    elif nav_choice == "3. File Integrity":
        from dashboard.pages_impl import file_integrity_view
        file_integrity_view.render()
    elif nav_choice == "4. Compare Files":
        from dashboard.pages_impl import compare_files_view
        compare_files_view.render()
    elif nav_choice == "5. Version Timeline":
        from dashboard.pages_impl import version_timeline_view
        version_timeline_view.render()
    elif nav_choice == "6. Integrity Chain":
        from dashboard.pages_impl import integrity_chain_view
        integrity_chain_view.render()
    elif nav_choice == "7. Evidence Reports":
        from dashboard.pages_impl import evidence_reports_view
        evidence_reports_view.render()
    elif nav_choice == "8. Security Guide":
        from dashboard.pages_impl import security_guide_view
        security_guide_view.render()
    elif nav_choice == "9. API Information":
        from dashboard.pages_impl import api_info_view
        api_info_view.render()
