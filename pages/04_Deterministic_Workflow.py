"""
🎯 Deterministic Workflow Test Page

Interactive web interface for testing deterministic multi-agent workflow
with real-time execution visualization and results display.
"""

import streamlit as st
import sys
import os
from datetime import datetime
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.graphs.deterministic import DeterministicWorkflowEngine
from src.utils.deterministic_state import ExecutionPhase, PhaseStatus
from frontend.web.components.theme_ui import ThemeUIComponent

# Initialize theme
theme_ui = ThemeUIComponent()


def init_session_state():
    """Initialize session state"""
    if "workflow_result" not in st.session_state:
        st.session_state.workflow_result = None
    if "execution_in_progress" not in st.session_state:
        st.session_state.execution_in_progress = False


def render_phase_badge(phase: str, status: str):
    """Render colored badge for phase status"""
    status_colors = {
        "completed": "🟢",
        "in_progress": "🟡",
        "failed": "🔴",
        "pending": "⚪",
        "skipped": "⚫"
    }
    icon = status_colors.get(status, "⚪")
    return f"{icon} **{phase.upper()}** - {status}"


def render_execution_log(logs):
    """Render execution log entries"""
    st.markdown("### 📝 Execution Log")
    
    for log in logs:
        validation_icon = "✅" if log.validated else "❌"
        
        with st.expander(f"{validation_icon} {log.phase.upper()} - {log.action}", expanded=False):
            col1, col2 = st.columns([1, 3])
            
            with col1:
                st.markdown("**Timestamp:**")
                st.markdown("**Agent:**")
                st.markdown("**Validated:**")
            
            with col2:
                st.markdown(log.timestamp)
                st.markdown(log.agent)
                st.markdown(f"{validation_icon} {log.validated}")
            
            st.markdown("---")
            st.markdown("**Reasoning:**")
            st.info(log.reasoning)
            
            st.markdown("**Result:**")
            st.success(log.result) if log.validated else st.error(log.result)


def render_phase_results(phase_results):
    """Render phase execution results"""
    st.markdown("### 🔄 Phase Execution Results")
    
    for result in phase_results:
        status_emoji = {
            PhaseStatus.COMPLETED: "✅",
            PhaseStatus.IN_PROGRESS: "🔄",
            PhaseStatus.FAILED: "❌",
            PhaseStatus.SKIPPED: "⏭️",
            PhaseStatus.PENDING: "⏸️"
        }
        
        emoji = status_emoji.get(result.status, "⚪")
        
        with st.expander(f"{emoji} {result.phase.value.upper()} - {result.status.value}", expanded=True):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Phase", result.phase.value)
                st.metric("Agent", result.agent)
            
            with col2:
                st.metric("Status", result.status.value)
                st.metric("Validated", "✅ Yes" if result.validation_passed else "❌ No")
            
            with col3:
                st.metric("Actions", len(result.actions_taken))
                st.metric("Timestamp", result.timestamp.split("T")[1][:8])
            
            if result.actions_taken:
                st.markdown("**Actions Taken:**")
                for action in result.actions_taken:
                    st.markdown(f"  • {action}")
            
            if result.findings:
                st.markdown("**Findings:**")
                st.json(result.findings)
            
            if result.reasoning:
                st.markdown("**Reasoning:**")
                st.info(result.reasoning)
            
            if result.error_message:
                st.markdown("**Error:**")
                st.error(result.error_message)


def render_executive_summary(summary):
    """Render executive summary dashboard"""
    st.markdown("### Executive Summary")
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Phases Executed",
            summary['phases_executed'],
            delta=None
        )
    
    with col2:
        objective_icon = "✅" if summary['objective_achieved'] else "❌"
        st.metric(
            "Objective",
            objective_icon,
            delta="Achieved" if summary['objective_achieved'] else "Not Met"
        )
    
    with col3:
        st.metric(
            "Risk Score",
            f"{summary['risk_score']}/10",
            delta=None
        )
    
    with col4:
        st.metric(
            "Services Found",
            summary['services_discovered'],
            delta=None
        )
    
    # Detailed info
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Target Information:**")
        st.markdown(f"  • Target: `{summary['target']}`")
        st.markdown(f"  • Objective: `{summary['objective']}`")
        st.markdown(f"  • Current Phase: `{summary['current_phase']}`")
        st.markdown(f"  • Security Posture: `{summary['security_posture']}`")
    
    with col2:
        st.markdown("**Completion Status:**")
        st.markdown(f"  • Recon Complete: {'✅' if summary['recon_complete'] else '❌'}")
        st.markdown(f"  • Access Obtained: {'✅' if summary['access_obtained'] else '❌'}")
        st.markdown(f"  • Execution Logs: {summary['execution_logs']}")
        st.markdown(f"  • Simulation Mode: {'✅' if summary['simulation_mode'] else '❌'}")


def render_determinism_proof(phase_results):
    """Render proof of deterministic execution"""
    st.markdown("### 🔬 Determinism Proof")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Sequential Execution:**")
        phases_order = [r.phase.value for r in phase_results]
        st.markdown("  → ".join(phases_order))
        
        st.markdown("\n**Validation Gates:**")
        validations = [r.validation_passed for r in phase_results]
        all_passed = all(validations)
        st.markdown(f"  All phases validated: {'✅ Yes' if all_passed else '❌ No'}")
    
    with col2:
        st.markdown("**Phase Status:**")
        for result in phase_results:
            status_icon = "✅" if result.validation_passed else "❌"
            st.markdown(f"  {status_icon} {result.phase.value}: {result.status.value}")


def main():
    """Main page function"""
    
    st.set_page_config(
        page_title="Deterministic Workflow Test",
        page_icon="🎯",
        layout="wide"
    )
    
    # Apply theme
    current_theme = "dark" if st.session_state.get('dark_mode', True) else "light"
    theme_ui.apply_theme_css(current_theme)
    theme_ui.render_corner_logo()
    
    init_session_state()
    
    # Header
    st.title("🎯 Deterministic Workflow Engine")
    st.caption("Test deterministic multi-agent security assessments with validation gates and full audit trails")
    
    st.markdown("---")
    
    # Configuration section
    st.markdown("## Configuration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        target = st.text_input(
            "Target",
            value=st.session_state.get("initial_access_target", "victim"),
            help="IP address or Docker container name"
        )
        
        # Lab Target Suggestions
        st.markdown("**Lab Targets:**")
        t_col1, t_col2 = st.columns(2)
        with t_col1:
            if st.button("🎯 victim", use_container_width=True, key="workflow_target_victim"):
                st.session_state.initial_access_target = "victim"
                st.rerun()
        with t_col2:
            if st.button("🎯 juice-shop", use_container_width=True, key="workflow_target_juice"):
                st.session_state.initial_access_target = "juice-shop"
                st.rerun()
    
    with col2:
        objective = st.selectbox(
            "Objective",
            options=[
                "security_assessment",
                "vulnerability_scan",
                "penetration_test",
                "full_access"
            ],
            help="Assessment objective determines execution phases"
        )
    
    with col3:
        simulation_mode = st.checkbox(
            "Simulation Mode",
            value=st.session_state.get("simulation_mode", True),
            help="Safe execution mode - no actual attacks"
        )
        st.session_state.simulation_mode = simulation_mode
    
    # Execution control
    st.markdown("---")
    st.markdown("## Execution")
    
    col1, col2, col3 = st.columns([2, 2, 1])
    
    with col1:
        if st.button("▶️ Execute Workflow", type="primary", use_container_width=True, disabled=st.session_state.execution_in_progress):
            st.session_state.execution_in_progress = True
            st.rerun()
    
    with col2:
        if st.button("🗑️ Clear Results", use_container_width=True, disabled=st.session_state.execution_in_progress):
            st.session_state.workflow_result = None
            st.rerun()
    
    with col3:
        if st.button("🔄 Reset", use_container_width=True):
            st.session_state.workflow_result = None
            st.session_state.execution_in_progress = False
            st.rerun()
    
    # Execute workflow if requested
    if st.session_state.execution_in_progress:
        st.markdown("---")
        
        progress_container = st.container()
        
        with progress_container:
            with st.spinner("🔄 Executing deterministic workflow..."):
                try:
                    # Create engine and execute
                    engine = DeterministicWorkflowEngine()
                    
                    result = engine.execute(
                        target=target,
                        objective=objective,
                        simulation_mode=simulation_mode
                    )
                    
                    st.session_state.workflow_result = result
                    st.session_state.execution_in_progress = False
                    
                    st.success("✅ Workflow executed successfully!")
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Execution failed: {str(e)}")
                    st.exception(e)
                    st.session_state.execution_in_progress = False
    
    # Display results if available
    if st.session_state.workflow_result:
        result = st.session_state.workflow_result
        
        st.markdown("---")
        
        # Executive Summary
        summary = result.get_execution_summary()
        render_executive_summary(summary)
        
        st.markdown("---")
        
        # Phase Results
        if result.phase_results:
            render_phase_results(result.phase_results)
        
        st.markdown("---")
        
        # Execution Log
        if result.execution_log:
            render_execution_log(result.execution_log)
        
        st.markdown("---")
        
        # Determinism Proof
        if result.phase_results:
            render_determinism_proof(result.phase_results)
        
        st.markdown("---")
        
        # Decisions Made
        if result.decisions_made:
            st.markdown("### Strategic Decisions")
            for idx, decision in enumerate(result.decisions_made, 1):
                with st.expander(f"Decision #{idx}: {decision.get('decision', 'Unknown')}", expanded=False):
                    st.json(decision)
        
        st.markdown("---")
        
        # Raw Data Export
        with st.expander("📦 Export Raw Data", expanded=False):
            st.markdown("**Complete Execution State:**")
            
            export_data = {
                "target": result.target,
                "objective": result.objective,
                "summary": summary,
                "phase_results": [
                    {
                        "phase": r.phase.value,
                        "status": r.status.value,
                        "agent": r.agent,
                        "validated": r.validation_passed,
                        "findings": r.findings
                    }
                    for r in result.phase_results
                ],
                "execution_log": [
                    {
                        "timestamp": log.timestamp,
                        "phase": log.phase,
                        "agent": log.agent,
                        "action": log.action,
                        "result": log.result,
                        "validated": log.validated
                    }
                    for log in result.execution_log
                ]
            }
            
            st.json(export_data)
            
            st.download_button(
                label="📥 Download JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"deterministic_workflow_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    # Info section
    st.markdown("---")
    st.markdown("### About Deterministic Workflow")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.info("""
        **🔒 Safety**
        - Target validation
        - Simulation mode default
        - Multi-layer checks
        - No phase jumping
        """)
    
    with col2:
        st.info("""
        **✅ Validation**
        - Prerequisites enforced
        - Phase completion verified
        - Sequential execution
        - Full audit trail
        """)
    
    with col3:
        st.info("""
        **📊 Explainability**
        - Every action logged
        - Reasoning documented
        - Decisions tracked
        - Reproducible results
        """)


if __name__ == "__main__":
    main()
