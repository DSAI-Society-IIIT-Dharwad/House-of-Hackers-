"""
Reset Password Page

Streamlit page for completing password reset with token.
"""

import streamlit as st
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.components.reset_password_ui import ResetPasswordComponent
from frontend.web.utils.constants import ICON

st.set_page_config(
    page_title="Decepticon - Reset Password",
    page_icon=ICON,
    layout="wide",
    initial_sidebar_state="collapsed"
)

def main():
    # Get token from URL query params
    query_params = st.query_params
    token = query_params.get("token")
    
    reset_page = ResetPasswordComponent(token=token)
    reset_page.render()

if __name__ == "__main__":
    main()
