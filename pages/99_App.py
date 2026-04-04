import sys
import os

# Ensure project root is on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.utils.auth_utils import is_authenticated


def main():
    if not is_authenticated():
        import streamlit as st
        st.switch_page("pages/00_Login_Optimized.py")
        st.stop()

    from frontend import streamlit_app

    streamlit_app.main()


if __name__ == "__main__":
    main()
