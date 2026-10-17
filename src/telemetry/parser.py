"""Multi-cloud telemetry parser and normalizer for AWS, Azure, and GCP audit logs."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Union
import pandas as pd
from src.config import HIGH_RISK_IAM_ACTIONS, GEO_COORDINATES


def ip_to_country_fallback(ip_str: str) -> str:
    """Heuristic country mapping for mock / demonstration IP telemetry."""
    if not ip_str or ip_str == "unknown":
        return "USA"
    # Deterministic mapping for standard mock subnets
    if ip_str.startswith("194.26.") or ip_str.startswith("185.220."):
        return "RUS"
    elif ip_str.startswith("175.45."):
        return "PRK"
    elif ip_str.startswith("5.253."):
        return "IRN"
    elif ip_str.startswith("188.130."):
        return "ROU"
    elif ip_str.startswith("105.112."):
        return "NGA"
    elif ip_str.startswith("140.82.") or ip_str.startswith("192.168.") or ip_str.startswith("10."):
        return "USA"
    elif ip_str.startswith("51.140."):
        return "GBR"
    elif ip_str.startswith("35.156."):
        return "DEU"
    elif ip_str.startswith("13.232."):
        return "IND"
    elif ip_str.startswith("13.239."):
        return "AUS"
    return "USA"


def parse_aws_cloudtrail_records(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Parse AWS CloudTrail JSON records into standard normalized schema."""
    rows = []
    for r in records:
        event_name = r.get("eventName", "UnknownAction")
        user_identity = r.get("userIdentity", {})
        principal = (
            user_identity.get("userName")
            or user_identity.get("arn", "").split("/")[-1]
            or user_identity.get("principalId", "UnknownUser")
        )
        principal_type = user_identity.get("type", "IAMUser")
        source_ip = r.get("sourceIPAddress", "127.0.0.1")
        error_code = r.get("errorCode", "")
        status = "Failure" if error_code else "Success"
        raw_time = r.get("eventTime", datetime.now(timezone.utc).isoformat())

        # Determine country
        country_code = r.get("countryCode") or ip_to_country_fallback(source_ip)
        country_name = GEO_COORDINATES.get(country_code, {}).get("name", country_code)

        service = r.get("eventSource", "aws").replace(".amazonaws.com", "")
        is_sensitive = int(event_name in HIGH_RISK_IAM_ACTIONS)

        rows.append(
            {
                "timestamp": pd.to_datetime(raw_time),
                "provider": "AWS",
                "service": service,
                "event_name": event_name,
                "principal": principal,
                "principal_type": principal_type,
                "source_ip": source_ip,
                "country_code": country_code,
                "country_name": country_name,
                "status": status,
                "error_code": error_code,
                "is_error": 1 if error_code else 0,
                "is_sensitive_action": is_sensitive,
            }
        )
    return pd.DataFrame(rows)


def parse_azure_activity_records(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Parse Azure Activity Log JSON records into standard normalized schema."""
    rows = []
    for r in records:
        op_info = r.get("operationName", {})
        event_name = op_info.get("value") if isinstance(op_info, dict) else str(op_info)
        principal = r.get("caller", "azure_user@domain.com")
        status_info = r.get("status", {})
        status_val = status_info.get("value") if isinstance(status_info, dict) else str(status_info)
        is_failure = status_val.lower() in ["failed", "failure", "denied"]
        source_ip = r.get("callerIpAddress", "10.0.0.1")
        raw_time = r.get("eventTimestamp", datetime.now(timezone.utc).isoformat())

        country_code = r.get("countryCode") or ip_to_country_fallback(source_ip)
        country_name = GEO_COORDINATES.get(country_code, {}).get("name", country_code)

        rows.append(
            {
                "timestamp": pd.to_datetime(raw_time),
                "provider": "Azure",
                "service": "AzureResource",
                "event_name": event_name.split("/")[-1] if "/" in event_name else event_name,
                "principal": principal,
                "principal_type": "ServicePrincipal" if "app" in principal.lower() else "User",
                "source_ip": source_ip,
                "country_code": country_code,
                "country_name": country_name,
                "status": "Failure" if is_failure else "Success",
                "error_code": "AccessDenied" if is_failure else "",
                "is_error": 1 if is_failure else 0,
                "is_sensitive_action": int(event_name in HIGH_RISK_IAM_ACTIONS),
            }
        )
    return pd.DataFrame(rows)


def parse_generic_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize arbitrary CSV / DataFrame into the standard schema."""
    normalized = pd.DataFrame()
    # Normalize timestamp
    time_col = next((c for c in df.columns if "time" in c.lower() or "date" in c.lower()), None)
    if time_col:
        normalized["timestamp"] = pd.to_datetime(df[time_col])
    else:
        normalized["timestamp"] = pd.date_range(
            end=datetime.now(timezone.utc), periods=len(df), freq="5min"
        )

    normalized["provider"] = df["provider"] if "provider" in df.columns else "AWS"
    normalized["service"] = df["service"] if "service" in df.columns else "iam"

    name_col = next((c for c in df.columns if "event" in c.lower() or "action" in c.lower()), None)
    normalized["event_name"] = df[name_col] if name_col else "DescribeInstances"

    user_col = next(
        (
            c
            for c in df.columns
            if "user" in c.lower() or "principal" in c.lower() or "caller" in c.lower()
        ),
        None,
    )
    normalized["principal"] = df[user_col] if user_col else "operator"
    normalized["principal_type"] = (
        df["principal_type"] if "principal_type" in df.columns else "IAMUser"
    )

    ip_col = next((c for c in df.columns if "ip" in c.lower()), None)
    normalized["source_ip"] = df[ip_col] if ip_col else "192.168.1.10"

    if "country_code" in df.columns:
        normalized["country_code"] = df["country_code"]
    else:
        normalized["country_code"] = normalized["source_ip"].apply(ip_to_country_fallback)

    normalized["country_name"] = normalized["country_code"].apply(
        lambda cc: GEO_COORDINATES.get(cc, {}).get("name", str(cc))
    )

    status_col = next((c for c in df.columns if "status" in c.lower()), None)
    if status_col:
        normalized["status"] = df[status_col]
        normalized["is_error"] = normalized["status"].apply(
            lambda s: 1 if str(s).lower() in ["failure", "failed", "denied", "error"] else 0
        )
    else:
        normalized["status"] = "Success"
        normalized["is_error"] = 0

    normalized["error_code"] = df["error_code"] if "error_code" in df.columns else ""
    normalized["is_sensitive_action"] = normalized["event_name"].apply(
        lambda e: 1 if e in HIGH_RISK_IAM_ACTIONS else 0
    )

    # Time features
    normalized["hour_of_day"] = normalized["timestamp"].dt.hour
    normalized["day_of_week"] = normalized["timestamp"].dt.dayofweek
    return normalized


def parse_telemetry_payload(data: Union[str, bytes, Dict[str, Any], pd.DataFrame]) -> pd.DataFrame:
    """Intelligently parse raw JSON, CSV, or dictionary payload into a normalized DataFrame."""
    if isinstance(data, pd.DataFrame):
        df = parse_generic_dataframe(data)
    elif isinstance(data, (str, bytes)):
        try:
            parsed_json = json.loads(data)
            if isinstance(parsed_json, dict) and "Records" in parsed_json:
                df = parse_aws_cloudtrail_records(parsed_json["Records"])
            elif isinstance(parsed_json, list):
                if parsed_json and "eventName" in parsed_json[0]:
                    df = parse_aws_cloudtrail_records(parsed_json)
                elif parsed_json and "operationName" in parsed_json[0]:
                    df = parse_azure_activity_records(parsed_json)
                else:
                    df = parse_generic_dataframe(pd.DataFrame(parsed_json))
            elif isinstance(parsed_json, dict):
                df = parse_generic_dataframe(pd.DataFrame([parsed_json]))
            else:
                raise ValueError("Unrecognized JSON log format")
        except (json.JSONDecodeError, ValueError):
            import io

            if isinstance(data, bytes):
                data = data.decode("utf-8")
            raw_csv = pd.read_csv(io.StringIO(data))
            df = parse_generic_dataframe(raw_csv)
    elif isinstance(data, dict):
        if "Records" in data:
            df = parse_aws_cloudtrail_records(data["Records"])
        else:
            df = parse_generic_dataframe(pd.DataFrame([data]))
    else:
        raise ValueError(f"Unsupported telemetry data type: {type(data)}")

    # Ensure time features are present
    if "hour_of_day" not in df.columns and "timestamp" in df.columns:
        df["hour_of_day"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek

    return df.sort_values(by="timestamp").reset_index(drop=True)
