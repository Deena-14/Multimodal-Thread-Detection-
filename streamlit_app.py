"""
Streamlit Dashboard for Multimodal LLM-Based Threat Detection
Real-time visualization and management of security threats
"""

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import logging
import json
from typing import Dict, List, Any

from config import SystemConfig
from multimodal_processor import MultimodalDataProcessor
from llm_analysis import LLMThreatAnalyzer, ThreatAlertGenerator
from threat_alert import ThreatAlertManager, AlertNotifier
from network_capture import NetworkCapture

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set Streamlit page config
st.set_page_config(
    page_title="🔒 Multimodal LLM Threat Detection",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
    }
    .critical-alert {
        background-color: #ffcccc;
        border-left: 4px solid #ff0000;
        padding: 10px;
        border-radius: 4px;
    }
    .high-alert {
        background-color: #ffe6cc;
        border-left: 4px solid #ff6600;
        padding: 10px;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

class ThreatDetectionDashboard:
    """Main dashboard application"""
    
    def __init__(self):
        self.config = SystemConfig()
        self.processor = MultimodalDataProcessor(self.config.PROCESSING_CONFIG)
        self.analyzer = LLMThreatAnalyzer(self.config.LLM_CONFIG)
        self.notifier = AlertNotifier(self.config.ALERT_CONFIG)
        self.network_capture = NetworkCapture(self.config.NETWORK_CONFIG)
        # Persist alert_manager in session_state so alerts survive Streamlit reruns
        if 'alert_manager' not in st.session_state:
            st.session_state.alert_manager = ThreatAlertManager()
        self.alert_manager = st.session_state.alert_manager
    
    def render_header(self):
        """Render dashboard header"""
        col1, col2, col3 = st.columns([2, 2, 1])
        
        with col1:
            st.title("🔒 Multimodal LLM Threat Detection")
            st.markdown("*Context-Aware Security Analysis for Communication Systems*")
        
        with col3:
            st.metric("Current Time", datetime.now().strftime("%H:%M:%S"))
    
    def render_metrics(self):
        """Render key metrics"""
        col1, col2, col3, col4 = st.columns(4)
        
        active_alerts = len([a for a in self.alert_manager.alerts if a['status'] == 'active'])
        critical_alerts = len([a for a in self.alert_manager.alerts if a['risk_level'] == 'critical'])
        
        with col1:
            st.metric("Active Alerts", active_alerts, delta=active_alerts)
        
        with col2:
            st.metric("Critical Threats", critical_alerts, delta=critical_alerts)
        
        with col3:
            total_events = len(self.alert_manager.alerts)
            st.metric("Total Events", total_events)
        
        with col4:
            avg_risk = sum(a.get('risk_score', a.get('overall_risk_score', 0)) for a in self.alert_manager.alerts) / len(self.alert_manager.alerts) if self.alert_manager.alerts else 0
            st.metric("Avg Risk Score", f"{avg_risk:.2f}")
    
    def render_threat_analysis_section(self):
        """Render threat analysis section"""
        st.header("📊 Threat Analysis")

        col1, col2 = st.columns([1, 1])
        
        with col1:
            if st.button("🔍 Run Threat Detection", key="detect_btn"):
                with st.spinner("Processing multimodal data..."):
                    external = st.session_state.get('external_dataset', None)
                    if external:
                        st.info("📂 Using uploaded dataset for analysis.")
                    # Pass external dataset if available, else use simulator
                    data = self.processor.process_all(external=external)
                    analysis_result = self.analyzer.perform_threat_analysis(data['llm_input'])
                    
                    if analysis_result.get('threat_detected', False):
                        alert = self.alert_manager.create_alert(analysis_result)
                        self.notifier.broadcast_alert(alert)
                        st.warning("⚠️ Threat detected!")
                    else:
                        st.success("✅ Analysis completed! No threats found.")
                    
                    # Clean summary instead of raw JSON
                    ta = analysis_result.get('threat_analysis', {})
                    st.markdown("---")
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Threat Type", ta.get('threat_type', 'N/A').replace('_', ' ').title())
                    col_b.metric("Risk Level", analysis_result.get('overall_risk_level', 'N/A').upper())
                    col_c.metric("Risk Score", f"{analysis_result.get('overall_risk_score', 0):.2f}")
                    
                    col_d, col_e = st.columns(2)
                    col_d.metric("Confidence", f"{ta.get('confidence', 0):.0%}")
                    col_e.metric("Threat Detected", "Yes 🚨" if analysis_result.get('threat_detected') else "No ✅")
                    
                    if ta.get('pattern'):
                        st.info(f"📋 **Pattern:** {ta.get('pattern')}")
                    
                    if ta.get('affected_systems'):
                        st.warning(f"🖥️ **Affected Systems:** {', '.join(ta.get('affected_systems', []))}")
                    
                    if analysis_result.get('recommendations'):
                        recs = [r for r in analysis_result['recommendations'] if 'monitoring' not in r.lower() and 'document' not in r.lower()]
                        if recs:
                            st.markdown("**🛡️ Recommended Actions:**")
                            for r in recs[:4]:
                                st.markdown(f"- {r}")
        
        with col2:
            if st.button("🔄 Run Network Capture", key="capture_btn"):
                with st.spinner("Capturing network traffic..."):
                    packets = self.network_capture.capture_packets(packet_count=50)
                    flows = self.network_capture.analyze_flows()
                    suspicious = self.network_capture.detect_suspicious_patterns()
                    
                    st.success("✅ Capture completed!")
                    st.write(f"Captured {len(packets)} packets, {len(flows)} flows")
                    st.write(f"Suspicious patterns detected: {len(suspicious)}")


    
    def render_active_alerts_section(self):
        """Render active alerts"""
        st.header("⚠️ Active Alerts")
        
        if not self.alert_manager.alerts:
            st.info("No active alerts")
        else:
            # Filter options
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                options=['critical', 'high', 'medium', 'low'],
                default=['critical', 'high']
            )
            
            # Display alerts
            for alert in self.alert_manager.alerts:
                if alert['risk_level'] in risk_filter and alert['status'] == 'active':
                    self._render_alert_card(alert)
    
    def _render_alert_card(self, alert: Dict):
        """Render individual alert card"""
        risk_color_map = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        icon = risk_color_map.get(alert['risk_level'], '⚪')
        
        with st.container():
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                st.markdown(f"### {icon} {alert['threat_type'].upper()}")
                st.markdown(f"**Alert ID:** {alert['alert_id']}")
                st.markdown(f"**Description:** {alert['description']}")
            
            with col2:
                st.markdown(f"**Risk Level:** {alert['risk_level'].upper()}")
                st.markdown(f"**Risk Score:** {alert['risk_score']:.2f}")
                st.markdown(f"**Confidence:** {alert['confidence_score']:.2f}")
            
            with col3:
                # use plain-text buttons to avoid encoding/display issues
                ack_clicked = st.button("Acknowledge", key=f"ack_{alert['alert_id']}")
                res_clicked = st.button("Resolve", key=f"res_{alert['alert_id']}")
                if ack_clicked:
                    self.alert_manager.acknowledge_alert(alert['alert_id'])
                    st.success("Acknowledged!")
                    st.experimental_rerun()
                if res_clicked:
                    self.alert_manager.resolve_alert(alert['alert_id'])
                    st.success("Resolved!")
                    st.experimental_rerun()
            
            st.markdown(f"**Affected Systems:** {', '.join(alert['source_ips'])}")
            
            with st.expander("Recommended Actions"):
                for idx, action in enumerate(alert['actions_recommended']):
                    # create a button for each recommended action
                    btn_key = f"act_{alert['alert_id']}_{idx}"
                    if st.button(action, key=btn_key):
                        # record that the action was taken
                        alert.setdefault('actions_taken', []).append(action)
                        logger.info(f"Action taken for {alert['alert_id']}: {action}")
                        st.success(f"Action executed: {action}")
                        # you could place real logic here (isolate hosts, block IP, etc.)
                        st.experimental_rerun()
                # show any actions already performed
                if alert.get('actions_taken'):
                    st.markdown("**Actions already executed:**")
                    for a in alert['actions_taken']:
                        st.markdown(f"- {a}")
            
            st.divider()
    
    def render_statistics_section(self):
        """Render statistics and visualizations"""
        st.header("📈 Statistics & Analytics")
        
        if self.alert_manager.alerts:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                # Alerts by risk level
                alerts_df = pd.DataFrame(self.alert_manager.alerts)
                risk_counts = alerts_df['risk_level'].value_counts()
                
                fig, ax = plt.subplots()
                risk_counts.plot(kind='bar', color=['red', 'orange', 'yellow', 'green'], ax=ax)
                ax.set_title("Alerts by Risk Level")
                ax.set_xlabel("Risk Level")
                ax.set_ylabel("Count")
                st.pyplot(fig)
            
            with col2:
                # Alerts by threat type
                threat_counts = alerts_df['threat_type'].value_counts().head(10)
                
                fig, ax = plt.subplots()
                threat_counts.plot(kind='barh', ax=ax)
                ax.set_title("Top Threat Types")
                ax.set_xlabel("Count")
                st.pyplot(fig)
        else:
            st.info("No alert data to display")
    
    def render_configuration_section(self):
        """Render configuration panel"""
        st.header("⚙️ Configuration")
        
        with st.expander("Threat Detection Settings"):
            st.write("**Risk Threshold:**")
            risk_threshold = st.slider("Risk Score Threshold", 0.0, 1.0, 0.6)
            
            st.write("**Data Sources:**")
            for source in self.config.DATA_SOURCES:
                st.checkbox(source, value=self.config.DATA_SOURCES[source])
            
            st.write("**Alert Settings:**")
            alert_cooldown = st.number_input("Alert Cooldown (seconds)", 30, 600, 60)
        
        with st.expander("LLM Configuration"):
            st.write(f"**Model:** {self.config.LLM_CONFIG['model_name']}")
            st.write(f"**Temperature:** {self.config.LLM_CONFIG['temperature']}")
            st.write(f"**Max Tokens:** {self.config.LLM_CONFIG['max_tokens']}")
    
    def render_logs_section(self):
        """Render system logs"""
        st.header("📋 System Logs")
        
        if st.button("📥 Export Alerts"):
            alerts_json = json.dumps(self.alert_manager.alerts, indent=2, default=str)
            st.download_button(
                label="Download Alerts as JSON",
                data=alerts_json,
                file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
        
        # Display recent alerts as table
        if self.alert_manager.alerts:
            alerts_df = pd.DataFrame(self.alert_manager.alerts)
            selected_cols = ['alert_id', 'threat_type', 'risk_level', 'risk_score', 'status']
            st.dataframe(alerts_df[selected_cols], use_container_width=True)
        else:
            st.info("No alerts to display")
    
    def run(self):
        """Run the dashboard"""
        # ── Sidebar navigation ────────────────────────────────────────────────
        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Select Page:",
            ["Dashboard", "Threat Analysis", "Alerts", "Statistics", "Configuration", "Logs"])

        # ── Dataset upload — sidebar ──────────────────────────────────────────
        st.sidebar.markdown("---")
        st.sidebar.header("📂 Upload Dataset")
        st.sidebar.markdown(
            "Upload a **CSV** or **JSON** file to run detection on your own data "
            "instead of the built-in simulator."
        )

        uploaded_file = st.sidebar.file_uploader(
            "Choose file", type=["csv", "json"], key="dataset_uploader"
        )

        # Store parsed external data in session_state so it survives reruns
        if uploaded_file is not None:
            file_type = uploaded_file.name.rsplit('.', 1)[-1].lower()
            try:
                content = uploaded_file.read().decode('utf-8')
                external_data = self.processor.load_from_dataset(content, file_type)
                st.session_state['external_dataset'] = external_data
                total = sum(len(v) for v in external_data.values())
                st.sidebar.success(f"✅ Loaded {total} events from `{uploaded_file.name}`")
                breakdown = {k: len(v) for k, v in external_data.items() if v}
                st.sidebar.json(breakdown)
            except Exception as e:
                st.sidebar.error(f"❌ Failed to parse file: {e}")
                st.session_state.pop('external_dataset', None)
        else:
            if 'external_dataset' not in st.session_state:
                st.sidebar.info("ℹ️ No dataset uploaded — using simulated data.")

        if st.sidebar.button("🗑️ Clear Dataset", key="clear_dataset"):
            st.session_state.pop('external_dataset', None)
            st.sidebar.success("Dataset cleared. Back to simulated data.")

        # ── Render header ─────────────────────────────────────────────────────
        self.render_header()
        st.divider()

        # Render selected page
        if page == "Dashboard":
            self.render_metrics()
            st.divider()
            self.render_threat_analysis_section()
            st.divider()
            self.render_active_alerts_section()

        elif page == "Threat Analysis":
            self.render_threat_analysis_section()

        elif page == "Alerts":
            self.render_active_alerts_section()

        elif page == "Statistics":
            self.render_statistics_section()

        elif page == "Configuration":
            self.render_configuration_section()

        elif page == "Logs":
            self.render_logs_section()

def main():
    """Main entry point"""
    dashboard = ThreatDetectionDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()