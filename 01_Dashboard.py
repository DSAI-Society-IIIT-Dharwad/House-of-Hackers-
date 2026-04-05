
import streamlit as st
from frontend.web.components.dashboard import DashboardComponent
from frontend.web.components.theme_ui import ThemeUIComponent
from frontend.web.utils.auth_utils import is_authenticated

# Page Configuration
st.set_page_config(
    page_title="Decepticon Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Theme
theme_ui = ThemeUIComponent()
theme_ui.apply_theme_css(st.session_state.get("theme", "dark"))
theme_ui.render_corner_logo()

def main():
    # Authentication Check
    if not is_authenticated():
        st.switch_page("pages/00_Login_Optimized.py")
        st.stop()
        
    # Render Dashboard
    dashboard = DashboardComponent()
    dashboard.render()
    
    # Hide default Streamlit elements
    st.markdown("""
        <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
        </style>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
