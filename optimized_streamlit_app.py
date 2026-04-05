"""
Optimized Streamlit App

Applying Vercel React best practices for optimal performance.
"""

import streamlit as st
import sys
import os
from typing import Dict, Any, Optional
import time

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frontend.web.components.optimized_app import OptimizedAppComponent, performance_monitor, LazyComponent
from frontend.web.components.theme_ui import ThemeUIComponent
from frontend.web.core.app_state import AppState
from frontend.web.core.model_manager import ModelManager
from frontend.web.core.executor_manager import ExecutorManager
from frontend.web.utils.constants import ICON
from config.config import get_config


@performance_monitor
def initialize_session_state():
    """Initialize session state with performance optimizations"""
    # Use lazy initialization for expensive operations
    if "app_initialized" not in st.session_state:
        st.session_state.app_initialized = True
        
        # Initialize state managers
        if "app_state" not in st.session_state:
            st.session_state.app_state = AppState()
        
        # Cache configuration
        if "config" not in st.session_state:
            st.session_state.config = get_config()
        
        # Initialize managers lazily
        if "model_manager" not in st.session_state:
            st.session_state.model_manager = None
        
        if "executor_manager" not in st.session_state:
            st.session_state.executor_manager = None
        
        # Performance metrics
        if "performance_metrics" not in st.session_state:
            st.session_state.performance_metrics = {
                "page_load_time": time.time(),
                "interactions": 0
            }


@performance_monitor
def get_model_manager() -> ModelManager:
    """Get or create model manager with caching"""
    if st.session_state.model_manager is None:
        st.session_state.model_manager = ModelManager()
    return st.session_state.model_manager


@performance_monitor
def get_executor_manager() -> ExecutorManager:
    """Get or create executor manager with caching"""
    if st.session_state.executor_manager is None:
        st.session_state.executor_manager = ExecutorManager()
    return st.session_state.executor_manager


def render_model_selection():
    """Render optimized model selection"""
    model_manager = get_model_manager()
    
    # Cache model groups
    if "model_groups" not in st.session_state:
        st.session_state.model_groups = model_manager.get_model_groups()
    
    model_groups = st.session_state.model_groups
    
    # Render selection
    selected_provider = st.selectbox(
        "Select Model Provider",
        options=list(model_groups.keys()),
        key="model_provider"
    )
    
    if selected_provider:
        models = model_groups[selected_provider]
        selected_model = st.selectbox(
            "Select Model",
            options=models,
            key="model_selection"
        )
        
        if st.button("Initialize Model", type="primary"):
            initialize_model(selected_provider, selected_model)


@performance_monitor
def initialize_model(provider: str, model: str):
    """Initialize model with performance monitoring"""
    model_manager = get_model_manager()
    executor_manager = get_executor_manager()
    
    with st.spinner("Initializing model..."):
        try:
            # Initialize model
            model_manager.initialize_model(provider, model)
            
            # Initialize executor
            executor_manager.initialize_executor(provider, model)
            
            # Update session state
            st.session_state.model_initialized = True
            st.session_state.current_model = model
            st.session_state.current_provider = provider
            
            st.success(f"Model {model} initialized successfully!")
            
            # Navigate to chat
            time.sleep(1)
            st.switch_page("pages/01_Chat.py")
            
        except Exception as e:
            st.error(f"Failed to initialize model: {str(e)}")


def render_optimized_ui():
    """Render optimized UI with performance considerations"""
    # Apply theme once
    theme_ui = ThemeUIComponent()
    theme_ui.apply_theme_css("dark")
    
    # Apply optimized CSS
    st.markdown("""
    <style>
    /* Performance optimizations */
    .stApp {
        contain: layout style paint;
    }
    
    /* Optimize images */
    img {
        content-visibility: auto;
        loading: lazy;
    }
    
    /* GPU acceleration for animations */
    .gpu-accelerated {
        transform: translateZ(0);
        backface-visibility: hidden;
    }
    
    /* Reduce paint operations */
    .optimized-container {
        contain: layout style paint;
    }
    
    /* Optimize font loading */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    body {
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Main container
    st.markdown('<div class="optimized-container">', unsafe_allow_html=True)
    
    # Header
    render_header()
    
    # Main content
    if "model_initialized" not in st.session_state or not st.session_state.model_initialized:
        render_model_selection()
    else:
        # Show initialized model info
        render_model_info()
    
    st.markdown('</div>', unsafe_allow_html=True)


@performance_monitor
def render_header():
    """Render optimized header"""
    config = get_config()
    
    st.markdown(f"""
    <div class="gpu-accelerated">
        <div class="text-center py-8">
            <h1 class="text-5xl font-bold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-blue-500">
                DECEPTICON
            </h1>
            <p class="text-xl text-gray-300 mb-2">Autonomous Red Team Platform</p>
            <p class="text-sm text-gray-400">Version {config.get('app_version', '1.0.0')}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)


@performance_monitor
def render_model_info():
    """Render current model information"""
    current_model = st.session_state.get("current_model", "Unknown")
    current_provider = st.session_state.get("current_provider", "Unknown")
    
    st.markdown(f"""
    <div class="bg-gray-800 p-6 rounded-lg mb-6">
        <h3 class="text-lg font-semibold mb-2">Current Model</h3>
        <p class="text-gray-300">Provider: {current_provider}</p>
        <p class="text-gray-300">Model: {current_model}</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🔄 Change Model", use_container_width=True):
        st.session_state.model_initialized = False
        st.experimental_rerun()
    
    if st.button("💬 Start Chat", type="primary", use_container_width=True):
        st.switch_page("pages/01_Chat.py")


def render_performance_metrics():
    """Render performance metrics (development only)"""
    config = get_config()
    
    if not config.is_production and st.checkbox("Show Performance Metrics"):
        metrics = st.session_state.get("performance_metrics", {})
        
        st.markdown("### Performance Metrics")
        
        if "page_load_time" in metrics:
            load_time = time.time() - metrics["page_load_time"]
            st.metric("Page Load Time", f"{load_time:.3f}s")
        
        interactions = metrics.get("interactions", 0)
        st.metric("User Interactions", interactions)
        
        # Memory usage (if available)
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            st.metric("Memory Usage", f"{memory_mb:.1f} MB")
        except ImportError:
            pass


def track_interaction():
    """Track user interactions for performance monitoring"""
    if "performance_metrics" in st.session_state:
        st.session_state.performance_metrics["interactions"] += 1


def main():
    """Main optimized application"""
    # Configure page
    st.set_page_config(
        page_title="Decepticon - Autonomous Red Team",
        page_icon=ICON,
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Initialize session state
    initialize_session_state()
    
    # Track interaction
    track_interaction()
    
    # Render optimized UI
    render_optimized_ui()
    
    # Show performance metrics in development
    render_performance_metrics()


if __name__ == "__main__":
    main()
