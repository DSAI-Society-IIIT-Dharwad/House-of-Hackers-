"""
Registration Page - Optimized

Using performance-optimized components with Vercel best practices.
"""

import streamlit as st
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.components.optimized_register_ui import OptimizedRegisterPageComponent
from frontend.web.utils.constants import ICON

# Page config
st.set_page_config(
    page_title="Decepticon - Register",
    page_icon=ICON,
    layout="wide",
    initial_sidebar_state="collapsed"
)

def main():
    """Main registration page with optimizations"""
    # Check if already authenticated
    if st.session_state.get("authenticated") and st.session_state.get("user"):
        st.switch_page("pages/99_App.py")
        return
    

    # Show optimized registration interface
    register_page = OptimizedRegisterPageComponent()
    register_page.render()

if __name__ == "__main__":
    main()
