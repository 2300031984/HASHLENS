"""
HashLens SOC Dashboard Styling
Dark security/SOC-inspired theme with glowing indicators, clean typography,
and cyber-forensic card components.
"""

import streamlit as st


def apply_soc_theme():
    """Injects custom CSS for the security-focused SOC interface."""
    st.markdown(
        """
        <style>
            /* Main Application Background */
            .stApp {
                background-color: #0b0f19;
                color: #e2e8f0;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }

            /* Sidebar */
            [data-testid="stSidebar"] {
                background-color: #0f172a;
                border-right: 1px solid #1e293b;
            }

            /* Metric Cards */
            .soc-card {
                background: #131b2e;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                transition: transform 0.2s ease, border-color 0.2s ease;
            }
            .soc-card:hover {
                border-color: #00f0ff;
                transform: translateY(-2px);
            }

            /* Stat Numbers */
            .stat-value {
                font-size: 32px;
                font-weight: 800;
                color: #00f0ff;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            .stat-label {
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.1em;
                color: #94a3b8;
                margin-bottom: 4px;
            }

            /* Hash Display Box */
            .hash-box {
                font-family: 'Consolas', 'Roboto Mono', monospace;
                background: #090d16;
                padding: 12px 16px;
                border-radius: 8px;
                border: 1px solid #1e293b;
                color: #38bdf8;
                word-break: break-all;
                font-size: 13px;
                margin-top: 6px;
                margin-bottom: 12px;
            }

            /* Status Badges */
            .badge-tag {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 6px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }
            .badge-green {
                background: rgba(16, 185, 129, 0.15);
                color: #10b981;
                border: 1px solid #10b981;
            }
            .badge-red {
                background: rgba(239, 68, 68, 0.15);
                color: #ef4444;
                border: 1px solid #ef4444;
            }
            .badge-blue {
                background: rgba(56, 189, 248, 0.15);
                color: #38bdf8;
                border: 1px solid #38bdf8;
            }
            .badge-yellow {
                background: rgba(245, 158, 11, 0.15);
                color: #f59e0b;
                border: 1px solid #f59e0b;
            }

            /* Table Styling */
            div[data-testid="stDataFrame"] {
                border: 1px solid #1e293b;
                border-radius: 8px;
            }

            /* Buttons */
            .stButton > button {
                background: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                font-weight: 600;
                transition: all 0.2s;
            }
            .stButton > button:hover {
                background: #00f0ff;
                color: #0b0f19;
                border-color: #00f0ff;
                box-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
            }

            /* Section Headers */
            .soc-header {
                font-size: 20px;
                font-weight: 700;
                color: #f8fafc;
                border-bottom: 2px solid #00f0ff;
                padding-bottom: 8px;
                margin-top: 24px;
                margin-bottom: 16px;
                letter-spacing: 0.05em;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )
