"""
Registration Page

User registration page with username/email/password form,
password strength validation, and automatic login after registration.
"""

import streamlit as st
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.components.register_ui import RegisterPageComponent
from frontend.web.components.theme_ui import ThemeUIComponent
from frontend.web.utils.constants import ICON

# Page config
st.set_page_config(
    page_title="Decepticon - Register",
    page_icon=ICON,
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Apply theme
theme_ui = ThemeUIComponent()
current_theme = "dark"  # Enforce dark theme for registration
theme_ui.apply_theme_css(current_theme)


def main():
    """Main registration page"""
    # Check if already authenticated
    if st.session_state.get("authenticated") and st.session_state.get("user"):
        st.switch_page("pages/99_App.py")
        return
    
    # Show registration interface
    register_page = RegisterPageComponent()
    register_page.render()


if __name__ == "__main__":
    main()
