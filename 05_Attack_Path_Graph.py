"""
Attack path graph page for the hackathon demo flow.
"""

import os
import sys

import streamlit as st
import streamlit.components.v1 as components


sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from frontend.web.components.theme_ui import ThemeUIComponent
from frontend.web.utils.auth_utils import is_authenticated
from skills.k8s_attack_path_visualizer.visualizer import (
    DEFAULT_HTML_PATH,
    DEFAULT_MOCK_PATH,
    render_visualizer_html,
    write_visualizer_html,
)


theme_ui = ThemeUIComponent()


def _load_html(data_source: str) -> tuple[str, str]:
    """Load the requested graph HTML and gracefully fall back for live mode."""
    try:
        return render_visualizer_html(data_source), data_source
    except ValueError as exc:
        if data_source != "kubectl":
            raise
        st.warning(f"{exc} Falling back to the mock cluster so the graph still renders for the demo.")
        return render_visualizer_html(DEFAULT_MOCK_PATH), DEFAULT_MOCK_PATH


def main() -> None:
    """Render the attack-path graph page."""
    st.set_page_config(
        page_title="Attack Path Graph",
        page_icon="🕸️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    current_theme = "dark" if st.session_state.get("dark_mode", True) else "light"
    theme_ui.apply_theme_css(current_theme)
    theme_ui.render_corner_logo()

    if not is_authenticated():
        st.switch_page("pages/00_Login_Optimized.py")
        st.stop()

    st.title("Attack Path Graph")
    st.caption("Judge-friendly cluster visualization with shortest routes, blast radius, CVE exposure, and ranked choke points.")

    source_label = st.radio(
        "Dataset",
        options=["Mock Fixture", "Live kubectl (best effort)"],
        horizontal=True,
        help="Use the mock fixture for the polished demo path. Live mode depends on kubectl being installed and configured.",
    )
    requested_source = DEFAULT_MOCK_PATH if source_label == "Mock Fixture" else "kubectl"
    html_content, rendered_source = _load_html(requested_source)

    col1, col2, col3 = st.columns([1.1, 1.1, 2.8])
    with col1:
        if st.button("Write HTML Snapshot", use_container_width=True):
            snapshot_path = write_visualizer_html(
                data_source=rendered_source,
                output_path=DEFAULT_HTML_PATH,
            )
            st.success(f"Saved {snapshot_path}")
    with col2:
        st.download_button(
            "Download Graph HTML",
            data=html_content,
            file_name="attack_path_graph.html",
            mime="text/html",
            use_container_width=True,
        )
    with col3:
        active_label = "Live kubectl snapshot" if rendered_source == "kubectl" else "Mock fixture"
        st.info(f"Rendering: {active_label}")

    components.html(html_content, height=1120, scrolling=True)


if __name__ == "__main__":
    main()
