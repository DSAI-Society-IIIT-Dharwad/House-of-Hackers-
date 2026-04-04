"""
Forgot Password Page

Streamlit page for requesting password reset.
"""

import streamlit as st
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.components.forgot_password_ui import ForgotPasswordComponent
from frontend.web.utils.constants import ICON

st.set_page_config(
    page_title="Decepticon - Forgot Password",
    page_icon=ICON,
    layout="wide",
    initial_sidebar_state="collapsed"
)

def main():
    """Main forgot password page"""
    # Check if already authenticated
    if st.session_state.get("authenticated") and st.session_state.get("user"):
        st.switch_page("pages/99_App.py")
        return
    

    # Show forgot password interface
    forgot_page = ForgotPasswordComponent()
    forgot_page.render()

if __name__ == "__main__":
    main()
