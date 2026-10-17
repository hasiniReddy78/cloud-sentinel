"""CloudGuard IAM & CSPM Analyzer - Main Streamlit Application."""

import streamlit as st
import pandas as pd
from src.config import DEFAULT_CONTAMINATION
from src.telemetry.parser import parse_telemetry_payload
from src.telemetry.sample_data import get_sample_telemetry, get_sample_iam_hierarchy
from src.telemetry.generator import TelemetrySimulator
from src.analytics.anomaly_detector import AnomalyDetector
from src.analytics.iam_analyzer import IAMAnalyzer
from src.analytics.compliance_scorer import ComplianceEvaluator
from src.visualizer.styles import get_custom_css, render_metric_card
from src.visualizer.charts import (
    create_geo_choropleth_map,
    create_iam_sunburst_chart,
    create_anomaly_timeline,
    create_posture_gauge,
    create_event_breakdown_chart,
    create_compliance_sunburst,
)

# Page configuration
st.set_page_config(
    page_title="CloudGuard IAM & CSPM Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject modern dark-theme glassmorphism CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)


@st.cache_data
def load_default_data():
    """Cache default sample data to optimize render times."""
    return get_sample_telemetry(num_records=220), get_sample_iam_hierarchy()


def main():
    default_telemetry, default_hierarchy = load_default_data()

    # =========================================================================
    # Sidebar - Data Ingestion & ML Hyperparameter Controls
    # =========================================================================
    with st.sidebar:
        st.markdown("### 🛡️ **CloudGuard Platform**")
        st.caption("Cloud Security Posture & IAM Privilege Analyzer")
        st.divider()

        st.subheader("1. Telemetry Ingestion")
        source_mode = st.radio(
            "Select Telemetry Source:",
            [
                "Enterprise Baseline (AWS + Azure Injected Attacks)",
                "Dynamic Attack Simulator",
                "Upload Custom Audit Log (JSON/CSV)",
            ],
            index=0,
        )

        telemetry_df = default_telemetry.copy()
        hierarchy_df = default_hierarchy.copy()

        if source_mode == "Dynamic Attack Simulator":
            st.markdown("#### Simulator Controls")
            sim_events = st.slider(
                "Total Telemetry Events", min_value=100, max_value=800, value=250, step=50
            )
            sim_anomaly_rate = st.slider(
                "Anomaly Injection Rate", min_value=0.02, max_value=0.25, value=0.08, step=0.01
            )
            sim_seed = st.number_input("Random Seed", value=42, step=1)
            if st.button("⚡ Regenerate Traffic", use_container_width=True):
                simulator = TelemetrySimulator(seed=int(sim_seed))
                telemetry_df = simulator.generate(
                    total_events=sim_events, anomaly_rate=sim_anomaly_rate
                )
                st.success(f"Generated {len(telemetry_df)} audit events!")

        elif source_mode == "Upload Custom Audit Log (JSON/CSV)":
            st.markdown("#### Upload Cloud Audit Log")
            uploaded_file = st.file_uploader(
                "Upload AWS CloudTrail JSON, Azure Activity Log, or CSV",
                type=["json", "csv"],
            )
            if uploaded_file is not None:
                try:
                    payload = uploaded_file.read()
                    telemetry_df = parse_telemetry_payload(payload)
                    st.success(f"Successfully parsed {len(telemetry_df)} audit records!")
                except Exception as e:
                    st.error(f"Error parsing log payload: {str(e)}")
                    st.info("Falling back to enterprise baseline data.")
                    telemetry_df = default_telemetry.copy()

        st.divider()
        st.subheader("2. IsolationForest ML Tuning")
        contamination = st.slider(
            "Model Contamination Rate",
            min_value=0.01,
            max_value=0.20,
            value=DEFAULT_CONTAMINATION,
            step=0.01,
            help="Expected proportion of anomalies in the telemetry stream.",
        )

        st.divider()
        st.subheader("3. Telemetry Filters")
        available_providers = ["All"] + sorted(list(telemetry_df["provider"].unique()))
        selected_provider = st.selectbox("Cloud Provider Filter", available_providers)
        if selected_provider != "All":
            telemetry_df = telemetry_df[telemetry_df["provider"] == selected_provider]

        st.caption("Engine: scikit-learn 1.8 | Python 3.11 | Kubernetes v1.28")

    # =========================================================================
    # Run Analytics Pipeline (IsolationForest + IAM Analyzer + Compliance)
    # =========================================================================
    detector = AnomalyDetector(contamination=contamination)
    anomaly_result = detector.analyze(telemetry_df)
    analyzed_df = anomaly_result.analyzed_df

    iam_analyzer = IAMAnalyzer()
    iam_findings = iam_analyzer.audit_hierarchy(hierarchy_df)
    iam_metrics = iam_analyzer.get_summary_metrics(iam_findings)

    compliance_evaluator = ComplianceEvaluator()
    compliance_report = compliance_evaluator.evaluate(
        iam_findings=iam_findings,
        anomaly_count=anomaly_result.anomalies_detected,
    )

    # =========================================================================
    # Header Banner
    # =========================================================================
    st.markdown(
        '<div class="cloudguard-title-gradient">CloudGuard IAM & CSPM Analyzer</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="cloudguard-subtitle">Autonomous Cloud Security Posture Management, IsolationForest ML API Anomaly Detection & IAM Privilege Inheritance Hierarchy</div>',
        unsafe_allow_html=True,
    )

    # Top KPI Metrics Cards
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    with kpi_col1:
        st.markdown(
            render_metric_card(
                title="Audited Telemetry Events",
                value=f"{anomaly_result.total_events:,}",
                subtitle="AWS CloudTrail & Azure Activity logs",
                status="info",
            ),
            unsafe_allow_html=True,
        )
    with kpi_col2:
        st.markdown(
            render_metric_card(
                title="Behavioral Anomalies",
                value=f"{anomaly_result.anomalies_detected}",
                subtitle=f"{anomaly_result.anomaly_rate}% flagged by IsolationForest",
                status="critical" if anomaly_result.anomalies_detected > 0 else "success",
            ),
            unsafe_allow_html=True,
        )
    with kpi_col3:
        st.markdown(
            render_metric_card(
                title="IAM Escalation Vectors",
                value=f"{iam_metrics['critical'] + iam_metrics['high']}",
                subtitle=f"{iam_metrics['critical']} Critical Wildcard '*:*' Roles",
                status="warning" if iam_metrics["critical"] > 0 else "info",
            ),
            unsafe_allow_html=True,
        )
    with kpi_col4:
        st.markdown(
            render_metric_card(
                title="CSPM Posture Score",
                value=f"{compliance_report.overall_score}%",
                subtitle=f"{compliance_report.passed_controls} Passed / {compliance_report.failed_controls} Failed Controls",
                status=(
                    "success"
                    if compliance_report.overall_score >= 80
                    else ("warning" if compliance_report.overall_score >= 65 else "critical")
                ),
            ),
            unsafe_allow_html=True,
        )

    st.write("")

    # =========================================================================
    # Navigation Tabs
    # =========================================================================
    tab_overview, tab_geo, tab_iam, tab_compliance, tab_simulator, tab_devops = st.tabs(
        [
            "🧭 Executive Posture",
            "🌍 Geo-Threats & Anomaly ML",
            "🛡️ IAM Privilege Sunburst",
            "📋 CIS Benchmark Audit",
            "🔬 Intake & Attack Simulator",
            "🛠️ DevOps & CI/CD Pipeline",
        ]
    )

    # -------------------------------------------------------------------------
    # TAB 1: Executive Posture & Overview
    # -------------------------------------------------------------------------
    with tab_overview:
        col_gauge, col_events = st.columns([1, 2])
        with col_gauge:
            st.plotly_chart(
                create_posture_gauge(compliance_report.overall_score), use_container_width=True
            )
            st.markdown(
                f"""
                <div class="glass-card">
                    <b>Active Posture Summary:</b>
                    <ul style="margin-top: 0.5rem; font-size: 0.9rem; color: #cbd5e1;">
                        <li><b>Critical Threats:</b> {anomaly_result.critical_count} active incidents</li>
                        <li><b>Avg IAM Blast Radius:</b> {iam_metrics['average_blast_radius']}/100</li>
                        <li><b>Total Failed Controls:</b> {compliance_report.failed_controls} benchmarks</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_events:
            st.plotly_chart(create_event_breakdown_chart(analyzed_df), use_container_width=True)

        st.subheader("🚨 Priority Incident Triage & High-Threat Actors")
        if anomaly_result.top_threat_actors:
            actor_df = pd.DataFrame(anomaly_result.top_threat_actors)
            actor_df.columns = [
                "Principal / Identity",
                "Anomalous Actions",
                "Max Threat Score",
                "Severity Tier",
                "Last Country",
            ]
            st.dataframe(actor_df, use_container_width=True, hide_index=True)
        else:
            st.info("No high-risk threat actors detected in current telemetry stream.")

    # -------------------------------------------------------------------------
    # TAB 2: Geo-Threat & Behavioral Anomaly Detection
    # -------------------------------------------------------------------------
    with tab_geo:
        st.plotly_chart(create_geo_choropleth_map(analyzed_df), use_container_width=True)

        st.plotly_chart(create_anomaly_timeline(analyzed_df), use_container_width=True)

        st.subheader("🔍 Anomalous API Events Drilldown")
        flagged_df = analyzed_df[analyzed_df["is_anomaly"]].copy()
        if not flagged_df.empty:
            view_cols = [
                "timestamp",
                "principal",
                "event_name",
                "provider",
                "source_ip",
                "country_name",
                "threat_level",
                "anomaly_score",
                "anomaly_reasons",
            ]
            st.dataframe(flagged_df[view_cols], use_container_width=True, hide_index=True)
        else:
            st.success("Zero anomalies detected matching the current threshold.")

    # -------------------------------------------------------------------------
    # TAB 3: IAM Privilege & Blast Radius Hierarchy
    # -------------------------------------------------------------------------
    with tab_iam:
        st.markdown(
            "Explore the hierarchical privilege model from **Root Account ➔ Role Category ➔ Entity ➔ Attached Policy ➔ Permission**. Click on any segment to zoom and isolate blast radius."
        )
        st.plotly_chart(create_iam_sunburst_chart(hierarchy_df), use_container_width=True)

        st.subheader("⚠️ IAM Misconfigurations & Privilege Escalation Findings")
        for finding in iam_findings:
            sev_class = (
                "badge-critical"
                if finding.severity == "CRITICAL"
                else ("badge-high" if finding.severity == "HIGH" else "badge-medium")
            )
            with st.expander(
                f"[{finding.severity}] {finding.finding_id}: {finding.entity_name} - {finding.category} (Blast Radius: {finding.blast_radius_score}/100)"
            ):
                st.markdown(f"**Entity:** `{finding.entity_name}` ({finding.entity_type})")
                st.markdown(
                    f"**Risk Severity:** <span class='badge {sev_class}'>{finding.severity}</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Description:** {finding.description}")
                st.markdown(f"**Remediation Action:** {finding.remediation}")
                if finding.policy_snippet:
                    st.code(finding.policy_snippet, language="json")

    # -------------------------------------------------------------------------
    # TAB 4: CIS / ISO Compliance Audit
    # -------------------------------------------------------------------------
    with tab_compliance:
        c_col1, c_col2 = st.columns([1, 1])
        with c_col1:
            st.plotly_chart(
                create_compliance_sunburst(compliance_report.controls_df), use_container_width=True
            )
        with c_col2:
            st.subheader("Domain Posture Scores")
            for domain, score in compliance_report.domain_scores.items():
                st.write(f"**{domain}**: {score}%")
                st.progress(score / 100.0)

        st.subheader("📋 CIS Benchmark Control Checklist")
        st.dataframe(
            compliance_report.controls_df[
                ["Control ID", "Domain", "Status", "Severity", "Title", "Remediation"]
            ],
            use_container_width=True,
            hide_index=True,
        )

    # -------------------------------------------------------------------------
    # TAB 5: Telemetry Intake & Attack Simulator
    # -------------------------------------------------------------------------
    with tab_simulator:
        st.subheader("🔬 Telemetry Intake & Threat Simulation Engine")
        st.markdown(
            "Synthesize multi-cloud attack sequences or export parsed audit feeds to test SIEM and DevSecOps integrations."
        )

        sim_col1, sim_col2 = st.columns([1, 1])
        with sim_col1:
            st.markdown("#### Export Current Findings")
            csv_data = analyzed_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download Analyzed Telemetry (CSV)",
                data=csv_data,
                file_name="cloudguard_threat_telemetry.csv",
                mime="text/csv",
                use_container_width=True,
            )

            # JSON export of flagged anomalies
            anom_json = analyzed_df[analyzed_df["is_anomaly"]].to_json(
                orient="records", date_format="iso"
            )
            st.download_button(
                "📥 Download Flagged Security Incidents (JSON)",
                data=anom_json,
                file_name="cloudguard_flagged_anomalies.json",
                mime="application/json",
                use_container_width=True,
            )

        with sim_col2:
            st.markdown("#### Raw Audit Sample Preview")
            st.json(telemetry_df.head(3).to_dict(orient="records"))

    # -------------------------------------------------------------------------
    # TAB 6: DevOps & CI/CD Pipeline Architecture
    # -------------------------------------------------------------------------
    with tab_devops:
        st.subheader("🛠️ DevOps Toolchain Integration Specs")
        st.markdown("""
            This application is engineered adhering to all 5 foundational DevOps specifications:
            """)

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown("""
            #### 1. Development & Workspace
            * **VS Code DevContainers**: Complete `.devcontainer/devcontainer.json` & `.devcontainer/Dockerfile` with Python 3.11, Trivy scanner, and VS Code extensions.
            * **WSL2 & Docker Desktop**: Fully containerized runtime with persistent local volume binding and headless execution.

            #### 2. App & Presentation Layer
            * **Python 3.11 / Streamlit**: Reactive analytical dashboard with scikit-learn `IsolationForest` ML and Plotly Express visualizations.
            * **Security Hardening**: Read-only root filesystem with non-root UID 10001 unprivileged security context.

            #### 3. Packaging & Containerization
            * **Multi-Stage Dockerfile**: Multi-stage build leveraging `python:3.11-slim`, separating build dependencies from the minimal runtime image.
            * **.dockerignore**: Excludes `.git`, `.venv`, cache files, and test artifacts.
            """)

        with d_col2:
            st.markdown("""
            #### 4. CI/CD Orchestration (GitHub Actions)
            * **Code Quality Gate**: Formatting verified via `black --check`, linting via `flake8`.
            * **Automated Unit Testing**: `pytest` covering telemetry ingestion, IsolationForest ML, and IAM hierarchy analysis.
            * **DevSecOps Security Gate**: Automated `trivy` filesystem & container image vulnerability scanning.
            * **Registry Publication**: Image published to GitHub Container Registry (`ghcr.io`).

            #### 5. Workload Orchestration (Kubernetes)
            * **Deployment & Service**: Managed via `k8s/deployment.yaml` with 2 replicas and `k8s/service.yaml` (LoadBalancer / NodePort 30851).
            * **Health Probes**: `livenessProbe` and `readinessProbe` targeting Streamlit's internal `/_stcore/health`.
            * **Configuration & Secrets**: Decoupled via `ConfigMap` and `Secret` objects.
            * **Autoscaling & Network Policy**: `HorizontalPodAutoscaler` (HPA) and zero-trust `NetworkPolicy`.
            """)

        st.subheader("Kubernetes Deployment Manifest Preview")
        with open("k8s/deployment.yaml", "r", encoding="utf-8") as f:
            st.code(f.read(), language="yaml")


if __name__ == "__main__":
    main()
