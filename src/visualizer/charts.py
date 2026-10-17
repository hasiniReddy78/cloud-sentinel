"""Interactive Plotly visualizations for CloudGuard."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict
from src.config import GEO_COORDINATES


def create_geo_choropleth_map(df: pd.DataFrame) -> go.Figure:
    """Choropleth world map with superimposed anomalous login scatter bubbles."""
    # Group events by country to calculate event and anomaly density
    country_summary = (
        df.groupby(["country_code", "country_name"])
        .agg(
            total_events=("timestamp", "count"),
            anomalies=("is_anomaly", "sum"),
            avg_threat=("anomaly_score", "mean"),
        )
        .reset_index()
    )

    # 1. Base Choropleth layer
    fig = px.choropleth(
        country_summary,
        locations="country_code",
        locationmode="ISO-3",
        color="avg_threat",
        color_continuous_scale="Viridis",
        range_color=[0.0, 1.0],
        hover_name="country_name",
        hover_data={
            "total_events": True,
            "anomalies": True,
            "avg_threat": ":.2f",
            "country_code": False,
        },
        labels={
            "avg_threat": "Threat Score",
            "anomalies": "Anomalies",
            "total_events": "Total Events",
        },
        title="<b>Global Telemetry Origin & Behavioral Threat Density</b>",
    )

    # 2. Add scattergeo points for specific anomalous logins
    anom_events = df[df["is_anomaly"]].copy()
    if not anom_events.empty:
        # Add lat/lon from coordinate lookup
        lats = []
        lons = []
        for cc in anom_events["country_code"]:
            geo = GEO_COORDINATES.get(cc, {"lat": 0.0, "lon": 0.0})
            lats.append(geo["lat"])
            lons.append(geo["lon"])
        anom_events["lat"] = lats
        anom_events["lon"] = lons

        fig.add_trace(
            go.Scattergeo(
                lat=anom_events["lat"],
                lon=anom_events["lon"],
                mode="markers",
                marker=dict(
                    size=12,
                    color="#ef4444",
                    symbol="triangle-up",
                    line=dict(width=1.5, color="#ffffff"),
                    opacity=0.9,
                ),
                text=anom_events.apply(
                    lambda r: f"<b>{r['principal']}</b><br>Action: {r['event_name']}<br>Threat: {r['threat_level']} ({r['anomaly_score']})<br>IP: {r['source_ip']}<br>Reasons: {r['anomaly_reasons']}",
                    axis=1,
                ),
                hoverinfo="text",
                name="Anomalous Event",
            )
        )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        margin=dict(l=0, r=0, t=45, b=0),
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor="rgba(71, 85, 105, 0.6)",
            projection_type="natural earth",
            bgcolor="rgba(15, 23, 42, 0)",
            lakecolor="rgba(15, 23, 42, 0)",
            showocean=False,
            countrycolor="rgba(71, 85, 105, 0.4)",
        ),
        coloraxis_colorbar=dict(
            title="Threat Index",
            thicknessmode="pixels",
            thickness=14,
            lenmode="pixels",
            len=250,
            yanchor="middle",
            y=0.5,
        ),
        legend=dict(orientation="h", yanchor="bottom", y=0.02, xanchor="right", x=1),
    )
    return fig


def create_iam_sunburst_chart(hierarchy_df: pd.DataFrame) -> go.Figure:
    """Plotly Sunburst chart depicting IAM Role -> Policy -> Permission hierarchy."""
    color_map: Dict[str, str] = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#06b6d4",
        "(?)": "#64748b",
    }

    fig = px.sunburst(
        hierarchy_df,
        path=["Account", "Category", "Entity", "Policy", "Permission"],
        values="Weight",
        color="Risk",
        color_discrete_map=color_map,
        title="<b>IAM Privilege & Blast Radius Inheritance Sunburst</b>",
    )

    fig.update_traces(
        textinfo="label+percent entry",
        insidetextorientation="radial",
        leaf=dict(opacity=0.9),
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        margin=dict(l=10, r=10, t=50, b=10),
        font=dict(family="Inter, sans-serif"),
    )
    return fig


def create_anomaly_timeline(df: pd.DataFrame) -> go.Figure:
    """Timeline scatter chart showing API calls, anomaly scores, and threat threshold."""
    fig = go.Figure()

    # Normal events trace
    normal = df[~df["is_anomaly"]]
    if not normal.empty:
        fig.add_trace(
            go.Scatter(
                x=normal["timestamp"],
                y=normal["anomaly_score"],
                mode="markers",
                name="Nominal Activity",
                marker=dict(size=6, color="#06b6d4", opacity=0.45),
                hovertext=normal.apply(
                    lambda r: f"<b>{r['principal']}</b>: {r['event_name']}<br>Score: {r['anomaly_score']}<br>Geo: {r['country_name']}",
                    axis=1,
                ),
                hoverinfo="text",
            )
        )

    # Anomalies trace
    anomalies = df[df["is_anomaly"]]
    if not anomalies.empty:
        fig.add_trace(
            go.Scatter(
                x=anomalies["timestamp"],
                y=anomalies["anomaly_score"],
                mode="markers",
                name="Flagged Threat Anomaly",
                marker=dict(
                    size=11,
                    color="#ef4444",
                    symbol="diamond",
                    line=dict(width=1.5, color="#ffffff"),
                    opacity=0.95,
                ),
                hovertext=anomalies.apply(
                    lambda r: f"<b>THREAT [{r['threat_level']}]</b><br>User: {r['principal']}<br>Action: {r['event_name']}<br>IP: {r['source_ip']} ({r['country_name']})<br>Score: {r['anomaly_score']}<br>Reason: {r['anomaly_reasons']}",
                    axis=1,
                ),
                hoverinfo="text",
            )
        )

    # Anomaly Threshold Reference Line
    fig.add_hline(
        y=0.60,
        line_dash="dash",
        line_color="#f59e0b",
        annotation_text="Anomaly Alert Threshold (0.60)",
        annotation_position="top left",
        annotation_font_color="#f59e0b",
    )

    fig.update_layout(
        template="plotly_dark",
        title="<b>Behavioral API Anomaly Score Timeline (IsolationForest)</b>",
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        xaxis=dict(title="Event Timestamp (UTC)", gridcolor="rgba(71, 85, 105, 0.25)"),
        yaxis=dict(
            title="IsolationForest Threat Index (0 - 1.0)",
            range=[-0.05, 1.05],
            gridcolor="rgba(71, 85, 105, 0.25)",
        ),
        margin=dict(l=30, r=30, t=50, b=30),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig


def create_posture_gauge(score: float) -> go.Figure:
    """Speedometer / Gauge chart for Cloud Security Posture Compliance Score."""
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "%", "font": {"size": 38, "family": "Inter", "color": "#f8fafc"}},
            title={
                "text": "<b>Cloud Security Posture (CSPM) Score</b>",
                "font": {"size": 15, "color": "#94a3b8"},
            },
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569"},
                "bar": {"color": "#6366f1", "thickness": 0.25},
                "bgcolor": "rgba(30, 41, 59, 0.5)",
                "borderwidth": 1,
                "bordercolor": "rgba(71, 85, 105, 0.5)",
                "steps": [
                    {"range": [0, 50], "color": "rgba(239, 68, 68, 0.35)"},
                    {"range": [50, 75], "color": "rgba(245, 158, 11, 0.35)"},
                    {"range": [75, 100], "color": "rgba(16, 185, 129, 0.35)"},
                ],
                "threshold": {
                    "line": {"color": "#10b981", "width": 4},
                    "thickness": 0.75,
                    "value": 85,
                },
            },
        )
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(15, 23, 42, 0)",
        plot_bgcolor="rgba(15, 23, 42, 0)",
        height=240,
        margin=dict(l=20, r=20, t=40, b=10),
    )
    return fig


def create_event_breakdown_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart of top API actions colored by sensitivity."""
    top_events = (
        df.groupby(["event_name", "is_sensitive_action"])
        .size()
        .reset_index(name="count")
        .sort_values(by="count", ascending=True)
        .tail(12)
    )
    top_events["Action Type"] = top_events["is_sensitive_action"].apply(
        lambda s: "Sensitive / IAM Privilege" if s == 1 else "Standard API Call"
    )

    fig = px.bar(
        top_events,
        x="count",
        y="event_name",
        color="Action Type",
        orientation="h",
        color_discrete_map={"Sensitive / IAM Privilege": "#ef4444", "Standard API Call": "#06b6d4"},
        title="<b>Top Cloud API Operations by Volume & Sensitivity</b>",
        labels={"count": "Invocations", "event_name": "API Action"},
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        margin=dict(l=10, r=20, t=45, b=20),
        xaxis=dict(gridcolor="rgba(71, 85, 105, 0.25)"),
        yaxis=dict(gridcolor="rgba(71, 85, 105, 0.25)"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig


def create_compliance_sunburst(controls_df: pd.DataFrame) -> go.Figure:
    """Sunburst chart for compliance status across domains."""
    df = controls_df.copy()
    df["Count"] = 1
    color_map = {"PASSED": "#10b981", "FAILED": "#ef4444", "WARNING": "#f59e0b"}

    fig = px.sunburst(
        df,
        path=["Framework", "Domain", "Status", "Control ID"],
        values="Count",
        color="Status",
        color_discrete_map=color_map,
        title="<b>CIS Foundations Control Status by Domain</b>",
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig
