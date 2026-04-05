"""
Model Selection Page 
"""

import streamlit as st
import asyncio
import time
import os
import sys
from dotenv import load_dotenv

# .env
load_dotenv()
load_dotenv(".env.local", override=True)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from frontend.web.components.model_selection import ModelSelectionComponent
from frontend.web.components.theme_ui import ThemeUIComponent

from frontend.web.core.app_state import get_app_state_manager
from frontend.web.core.executor_manager import get_executor_manager
from frontend.web.core.model_manager import get_model_manager

from frontend.web.utils.constants import ICON, ICON_TEXT, COMPANY_LINK

app_state = get_app_state_manager()
executor_manager = get_executor_manager()
model_manager = get_model_manager()

# UI 
theme_ui = ThemeUIComponent()
model_selection = ModelSelectionComponent()


def main():
    """"""
    
    # 
    st.set_page_config(
        page_title="Decepticon",
        page_icon=ICON,
        layout="wide",
    )
    
    # Apply theme
    current_theme = "dark" if st.session_state.get('dark_mode', True) else "light"
    theme_ui.apply_theme_css(current_theme)

    theme_ui.render_corner_logo()
    
    # Check authentication first - redirect to login if not authenticated
    from frontend.web.utils.auth_utils import is_authenticated
    if not is_authenticated():
        st.switch_page("pages/00_Login_Optimized.py")
        st.stop()
    
    # Display user menu for authenticated users
    from frontend.web.components.user_menu import UserMenuComponent
    user_menu = UserMenuComponent()
    user_menu.render()
    
    # 
    # st.logo(ICON_TEXT, icon_image=ICON, size="large", link=COMPANY_LINK)
    
    # 
    if st.session_state.get("initialization_in_progress", False):
        _handle_initialization_state()
        return
    
    #
    elif st.session_state.get("current_model") and st.session_state.get("executor_ready", False):
        st.switch_page("pages/01_Dashboard.py")
        return
    
    #
    elif st.session_state.get("current_model") and not st.session_state.get("executor_ready", False):
        st.session_state.initialization_in_progress = True
        st.rerun()
        return
    
    # 
    else:
        _display_model_selection()


def _handle_initialization_state():
    """"""
    model = st.session_state.get("current_model")
    if not model:
        st.session_state.initialization_in_progress = False
        st.rerun()
        return
    
    #  placeholder.container() 
    placeholder = st.empty()
    
    with placeholder.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # container
            _perform_model_initialization_in_container(model)


def _perform_model_initialization_in_container(model_info):
    """container """
    try:
        with st.spinner(f"Initializing {model_info.get('display_name', 'Model')}..."):
            success = asyncio.run(executor_manager.initialize_with_model(model_info))
        
        if success:
            st.session_state.executor_ready = True
            st.success(f"✅ {model_info.get('display_name', 'Model')} initialized successfully!")
            time.sleep(1.0)
            st.switch_page("pages/01_Dashboard.py")
        else:
            error_msg = st.session_state.get("initialization_error", "Unknown error")
            st.error(f"❌ Initialization failed: {error_msg}")
            
            # 재시도 버튼
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Retry", use_container_width=True):
                    st.rerun()
            with col2:
                if st.button("⬅️ Back", use_container_width=True):
                    st.session_state.current_model = None
                    st.session_state.initialization_in_progress = False
                    st.rerun()
    except Exception as e:
        st.error(f"❌ Initialization error: {str(e)}")
        
        # 
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Retry", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("⬅️ Back", use_container_width=True):
                st.session_state.current_model = None
                st.session_state.initialization_in_progress = False
                st.rerun()
    finally:
        st.session_state.initialization_in_progress = False



def _display_model_selection():
    """"""
    placeholder = st.empty()
    
    with placeholder.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            # 
            models_result = model_manager.get_cached_models_data()
            
            if not models_result["success"]:
                _handle_models_loading_error(models_result)
                return
            
            # Ollama 
            if models_result["type"] == "success" and "ollama_message" in models_result:
                model_selection.display_provider_status(models_result)
            
            # 
            default_provider, default_model = model_manager.get_default_selection()
            
            # 
            callbacks = {
                "on_model_change": _reset_model_selection,
                "get_export_data": lambda session_id: None  # 
            }
            
            # 
            selected_model = model_selection.render_complete_selection_ui(
                providers_data=models_result["models_by_provider"],
                current_model=st.session_state.get("current_model"),
                default_provider=default_provider,
                default_model=default_model,
                callbacks=callbacks
            )
            
            if selected_model:
                _handle_model_selection(selected_model)


def _handle_models_loading_error(models_result):
    """"""
    if models_result["type"] == "import_error":
        model_selection.display_error_state(
            models_result["error"],
            models_result.get("info")
        )
    else:
        model_selection.display_error_state(models_result["error"])


def _handle_model_selection(selected_model):
    """"""
    # 
    preparation_result = model_manager.prepare_model_initialization(selected_model)
    
    if not preparation_result["ready"]:
        st.error(f"Model validation failed: {', '.join(preparation_result['errors'])}")
        return
    
    #
    st.session_state.current_model = selected_model
    st.session_state.initialization_in_progress = True
    st.rerun()


def _reset_model_selection():
    """"""
    # 
    st.session_state.current_model = None
    st.session_state.executor_ready = False
    st.session_state.initialization_in_progress = False
    st.session_state.initialization_error = None
    
    # 
    executor_manager.reset()
    
    # 
    # model_manager.reset_cache()
    
    st.rerun()


if __name__ == "__main__":
    main()