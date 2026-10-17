"""Configuration and security reference constants for CloudGuard."""

import os
from typing import Dict, Set

# Runtime environment settings
APP_ENV: str = os.getenv("CLOUDGUARD_ENV", "development")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
DEFAULT_CONTAMINATION: float = float(os.getenv("ANOMALY_CONTAMINATION_RATE", "0.06"))

# High-risk IAM actions that represent privilege escalation or backdoor creation
HIGH_RISK_IAM_ACTIONS: Set[str] = {
    # AWS IAM High-Risk / Escalation API calls
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "PassRole",
    "AssumeRole",
    "CreateUser",
    "AddUserToGroup",
    "AuthorizeSecurityGroupIngress",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "DeleteTrail",
    "StopLogging",
    # Azure Role-Based Actions
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    # GCP IAM Actions
    "setIamPolicy",
    "serviceAccounts.keys.create",
    "serviceAccounts.actAs",
}

# Geolocation baseline reference (Country Code ISO-3, Name, Lat, Lon)
GEO_COORDINATES: Dict[str, Dict[str, float]] = {
    "USA": {"lat": 37.0902, "lon": -95.7129, "name": "United States"},
    "GBR": {"lat": 55.3781, "lon": -3.4360, "name": "United Kingdom"},
    "DEU": {"lat": 51.1657, "lon": 10.4515, "name": "Germany"},
    "FRA": {"lat": 46.2276, "lon": 2.2137, "name": "France"},
    "JPN": {"lat": 36.2048, "lon": 138.2529, "name": "Japan"},
    "SGP": {"lat": 1.3521, "lon": 103.8198, "name": "Singapore"},
    "IND": {"lat": 20.5937, "lon": 78.9629, "name": "India"},
    "AUS": {"lat": -25.2744, "lon": 133.7751, "name": "Australia"},
    "CAN": {"lat": 56.1304, "lon": -106.3468, "name": "Canada"},
    "BRA": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil"},
    # Unrecognized / High Threat Origin locations
    "RUS": {"lat": 61.5240, "lon": 105.3188, "name": "Russia"},
    "CHN": {"lat": 35.8617, "lon": 104.1954, "name": "China"},
    "PRK": {"lat": 40.3399, "lon": 127.5101, "name": "North Korea"},
    "IRN": {"lat": 32.4279, "lon": 53.6880, "name": "Iran"},
    "ROU": {"lat": 45.9432, "lon": 24.9668, "name": "Romania"},
    "NGA": {"lat": 9.0820, "lon": 8.6753, "name": "Nigeria"},
}

HIGH_RISK_COUNTRIES: Set[str] = {"RUS", "PRK", "IRN", "ROU", "NGA"}
HOME_COUNTRIES: Set[str] = {"USA", "GBR", "DEU", "IND", "CAN"}

# Severity thresholds
THREAT_LEVEL_THRESHOLDS = {
    "CRITICAL": 0.85,
    "HIGH": 0.65,
    "MEDIUM": 0.40,
    "LOW": 0.0,
}
