"""Unit tests for telemetry parsing and simulation."""

import json
from src.telemetry.parser import (
    parse_telemetry_payload,
    parse_aws_cloudtrail_records,
    parse_azure_activity_records,
    ip_to_country_fallback,
)
from src.telemetry.generator import TelemetrySimulator
from src.telemetry.sample_data import get_sample_telemetry, get_sample_iam_hierarchy


def test_ip_to_country_fallback():
    assert ip_to_country_fallback("194.26.29.1") == "RUS"
    assert ip_to_country_fallback("175.45.176.1") == "PRK"
    assert ip_to_country_fallback("5.253.204.1") == "IRN"
    assert ip_to_country_fallback("140.82.112.4") == "USA"
    assert ip_to_country_fallback("unknown") == "USA"


def test_parse_aws_cloudtrail_records():
    raw_records = [
        {
            "eventName": "DescribeInstances",
            "userIdentity": {"userName": "alice.dev", "type": "IAMUser"},
            "sourceIPAddress": "140.82.112.4",
            "errorCode": "",
            "eventTime": "2026-10-16T12:00:00Z",
            "eventSource": "ec2.amazonaws.com",
        },
        {
            "eventName": "CreateAccessKey",
            "userIdentity": {"userName": "attacker", "type": "IAMUser"},
            "sourceIPAddress": "194.26.29.112",
            "errorCode": "AccessDenied",
            "eventTime": "2026-10-16T12:05:00Z",
            "eventSource": "iam.amazonaws.com",
        },
    ]
    df = parse_aws_cloudtrail_records(raw_records)
    assert len(df) == 2
    assert "timestamp" in df.columns
    assert df.iloc[0]["principal"] == "alice.dev"
    assert df.iloc[0]["status"] == "Success"
    assert df.iloc[1]["status"] == "Failure"
    assert df.iloc[1]["is_sensitive_action"] == 1
    assert df.iloc[1]["country_code"] == "RUS"


def test_parse_azure_activity_records():
    azure_records = [
        {
            "eventTimestamp": "2026-10-16T10:00:00Z",
            "operationName": {"value": "Microsoft.Compute/virtualMachines/read"},
            "caller": "dev@azure.com",
            "status": {"value": "Succeeded"},
            "callerIpAddress": "51.140.88.2",
        }
    ]
    df = parse_azure_activity_records(azure_records)
    assert len(df) == 1
    assert df.iloc[0]["provider"] == "Azure"
    assert df.iloc[0]["status"] == "Success"


def test_parse_telemetry_payload_json():
    payload = json.dumps(
        {
            "Records": [
                {
                    "eventName": "ListBuckets",
                    "userIdentity": {"userName": "ci-bot"},
                    "sourceIPAddress": "10.0.0.1",
                    "eventTime": "2026-10-16T08:00:00Z",
                }
            ]
        }
    )
    df = parse_telemetry_payload(payload)
    assert len(df) == 1
    assert df.iloc[0]["event_name"] == "ListBuckets"


def test_telemetry_simulator():
    sim = TelemetrySimulator(seed=123)
    df = sim.generate(total_events=50, anomaly_rate=0.10)
    assert len(df) == 50
    assert "is_sensitive_action" in df.columns
    assert "hour_of_day" in df.columns
    assert df["is_sensitive_action"].sum() > 0


def test_sample_datasets():
    telem = get_sample_telemetry(num_records=100)
    assert len(telem) >= 80
    assert "principal" in telem.columns

    iam = get_sample_iam_hierarchy()
    assert len(iam) > 0
    assert "Entity" in iam.columns
    assert "Policy" in iam.columns
