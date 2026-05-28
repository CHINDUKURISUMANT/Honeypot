import streamlit as st
import pandas as pd
from api_client import api_post

def render_system_status(core_ok, sys_status):
    st.subheader("SYSTEM STATUS")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Core API Status**")
        if core_ok:
            st.success("ONLINE")
        else:
            st.error("OFFLINE")
            
        st.markdown("**LLM Status**")
        if not core_ok:
            st.error("UNKNOWN")
        elif sys_status.get("llm_warm", False):
            st.success("HOT / READY")
        elif sys_status.get("llm_available", False):
            st.warning("WARMING UP")
        else:
            st.error("OFFLINE")

    with col2:
        st.markdown("**Docker Status**")
        if core_ok and sys_status.get("docker_available", False):
            st.success("AVAILABLE")
        else:
            st.error("UNAVAILABLE")
            
        st.markdown("**Active AI Tier**")
        if core_ok:
            tier = sys_status.get("ai_mode", 3)
            if tier == 1:
                st.info("TIER 1 (Rule-Based)")
            elif tier == 2:
                st.info("TIER 2 (ML Standard)")
            else:
                st.info("TIER 3 (LLM Advanced)")
        else:
            st.error("UNKNOWN")


def render_controls(core_ok, http_running, ssh_running, current_tier):
    st.subheader("TRAP CONTROLS")
    
    if not core_ok:
        st.error("Cannot manage traps while API is offline.")
        return
        
    # HTTP Trap
    hc1, hc2 = st.columns([3, 1])
    hc1.markdown("**HTTP Trap** - Web Application Sandbox")
    if http_running:
        if hc2.button("Stop HTTP", use_container_width=True):
            api_post("/control/http/stop")
            st.rerun()
    else:
        if hc2.button("Start HTTP", use_container_width=True):
            api_post("/control/http/start")
            st.rerun()
            
    # SSH Trap
    sc1, sc2 = st.columns([3, 1])
    sc1.markdown("**SSH Trap** - Console Auth Sandbox")
    if ssh_running:
        if sc2.button("Stop SSH", use_container_width=True):
            api_post("/control/ssh/stop")
            st.rerun()
    else:
        if sc2.button("Start SSH", use_container_width=True):
            api_post("/control/ssh/start")
            st.rerun()
            
    st.markdown("---")
    st.subheader("AI INTELLIGENCE MODE")
    
    tier_options = {
        1: "Tier 1: High Speed / Rule-Based Deception",
        2: "Tier 2: Balanced / ML Classification",
        3: "Tier 3: Advanced / LLM Generative Responses"
    }
    
    selected_tier_str = st.radio(
        "Select Active Mode",
        options=list(tier_options.values()),
        index=current_tier - 1 if current_tier in [1,2,3] else 2,
        label_visibility="collapsed"
    )
    
    selected_tier = [k for k, v in tier_options.items() if v == selected_tier_str][0]
    if selected_tier != current_tier:
        if api_post("/control/ai_mode", {"mode": selected_tier}):
            st.rerun()

def render_threat_intel(df):
    st.subheader("THREAT INTELLIGENCE (Per IP)")
    if df.empty:
        st.info("No threat intelligence data available.")
        return
        
    def extract_ip(row):
        details = row.get("details")
        if isinstance(details, dict):
            return details.get("client_ip") or row.get("client_ip", "UNKNOWN")
        return row.get("client_ip", "UNKNOWN")

    df["ip"] = df.apply(extract_ip, axis=1)
    
    for col in ["ai_classification", "threat_level", "risk_score"]:
        if col not in df.columns:
            df[col] = None
            
    def count_contains(responses):
        return sum(1 for r in responses if isinstance(r, dict) and r.get("action") == "CONTAIN")

    ip_stats = df.groupby("ip").agg(
        Phase=("behaviour", lambda x: x.iloc[-1]),
        AI_Profile=("ai_classification", lambda x: x.iloc[-1]),
        Threat_Status=("threat_level", lambda x: x.iloc[-1]),
        Peak_Risk=("risk_score", "max"),
        Event_Count=("event_type", "count"),
        Contained=("response", count_contains),
    ).sort_values("Peak_Risk", ascending=False)
    
    st.dataframe(ip_stats, use_container_width=True)

def render_containments(events):
    st.subheader("CONTAINMENT LOG")
    
    contained = []
    for ev in reversed(events):
        resp = ev.get("response", {})
        if isinstance(resp, dict) and resp.get("action") == "CONTAIN":
            contained.append(ev)
            
    if not contained:
        st.info("No active containments.")
        return
        
    for ev in contained[:10]:
        details = ev.get("details", {}) or {}
        ip = details.get("client_ip") or ev.get("client_ip", "UNKNOWN")
        ts = ev.get("timestamp", "UNKNOWN")
        risk = ev.get("risk_score", 0.0)
        
        with st.expander(f"CONTAINED: {ip} | Risk: {risk} | {ts[:19]}"):
            st.markdown(f"**Trigger Behaviour:** {ev.get('behaviour', 'UNKNOWN')}")
            cmd = details.get("command") or details.get("payload", "")
            if cmd:
                st.markdown("**Payload / Command:**")
                st.code(cmd)
                
            out = ev.get("terminal_output", "")
            if out:
                st.markdown("**Generated Deception Payload:**")
                st.code(out)
