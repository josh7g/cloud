import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, send_file
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc, func
from models import ZapScanResult
from db_utils import create_db_engine
from zap_scanner import ZapScanOptions, ZapScannerWithProgress
from progress_tracking import (
    update_scan_progress,
    clear_scan_progress,
    get_redis_client,
)
import os
from typing import Optional


logger = logging.getLogger(__name__)

zap_bp = Blueprint("zap", __name__, url_prefix="/api/v1/zap")




# ============================================================================
# INPUT SANITIZATION - Security helper functions
# ============================================================================

def sanitize_string_input(value, max_length=500, allow_special=False):
    """Sanitize string input to prevent injection attacks"""
    if not isinstance(value, str):
        return value
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    value = value.replace('\x00', '')
    if not allow_special:
        dangerous_chars = ['<', '>', '"', "'", '\\', ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
        for char in dangerous_chars:
            value = value.replace(char, '')
    return value


def sanitize_request_data(data):
    """Recursively sanitize all string values in request data"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            allow_special = key in ['code_snippet', 'reason', 'description', 'message', 'fix_description', 'target']
            if isinstance(value, str):
                sanitized[key] = sanitize_string_input(value, allow_special=allow_special)
            elif isinstance(value, dict):
                sanitized[key] = sanitize_request_data(value)
            elif isinstance(value, list):
                sanitized[key] = [sanitize_request_data(item) if isinstance(item, (dict, str)) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, str):
        return sanitize_string_input(data)
    else:
        return data

# ============================================================================

def _sanitize_target_id(target: str) -> str:
    try:
        sanitized = (
            target.replace("://", "_")
            .replace("/", "_")
            .replace("?", "_")
            .replace("&", "_")
            .replace("#", "_")
        )
        return sanitized.strip("_")
    except Exception:
        return target


def analyze_security_headers(findings):
    """Analyze security headers configuration"""
    header_issues = {}
    critical_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Permissions-Policy",
    ]

    for finding in findings:
        finding_id = finding.get("id", "")

        # Security headers analysis
        if "Content Security Policy" in finding_id:
            header_issues["csp"] = {
                "status": "missing",
                "severity": "high",
                "description": "Content Security Policy not implemented",
                "impact": "Increased risk of XSS attacks",
            }
        elif "Clickjacking" in finding_id:
            header_issues["clickjacking"] = {
                "status": "vulnerable",
                "severity": "medium",
                "description": "Missing anti-clickjacking headers",
                "impact": "Risk of UI redress attacks",
            }
        elif "Strict-Transport-Security" in finding_id:
            header_issues["hsts"] = {
                "status": "missing",
                "severity": "high",
                "description": "HSTS header not set",
                "impact": "Risk of SSL stripping attacks",
            }
        elif "X-Content-Type-Options" in finding_id:
            header_issues["content_type"] = {
                "status": "missing",
                "severity": "medium",
                "description": "X-Content-Type-Options not set",
                "impact": "Risk of MIME sniffing attacks",
            }
        elif "Permissions Policy" in finding_id:
            header_issues["permissions_policy"] = {
                "status": "missing",
                "severity": "medium",
                "description": "Permissions-Policy header not set",
                "impact": "Reduced control over browser features",
            }

    # Calculate security headers score
    implemented_headers = len(critical_headers) - len(header_issues)
    security_score = (implemented_headers / len(critical_headers)) * 100

    return {
        "security_headers_score": round(security_score, 2),
        "missing_headers": header_issues,
        "recommendations": generate_header_recommendations(header_issues),
        "critical_headers_checked": critical_headers,
    }


def generate_header_recommendations(header_issues):
    """Generate specific header implementation recommendations"""
    recommendations = []

    if "csp" in header_issues:
        recommendations.append(
            {
                "priority": "high",
                "header": "Content-Security-Policy",
                "recommendation": "Implement CSP with default-src 'self' and restrict unsafe-inline",
                "example": "Content-Security-Policy: default-src 'self'; script-src 'self'",
                "implementation_effort": "low",
            }
        )

    if "hsts" in header_issues:
        recommendations.append(
            {
                "priority": "high",
                "header": "Strict-Transport-Security",
                "recommendation": "Implement HSTS with max-age of at least 31536000",
                "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "implementation_effort": "low",
            }
        )

    if "clickjacking" in header_issues:
        recommendations.append(
            {
                "priority": "medium",
                "header": "X-Frame-Options",
                "recommendation": "Implement X-Frame-Options to prevent clickjacking",
                "example": "X-Frame-Options: DENY",
                "implementation_effort": "low",
            }
        )

    if "content_type" in header_issues:
        recommendations.append(
            {
                "priority": "medium",
                "header": "X-Content-Type-Options",
                "recommendation": "Implement X-Content-Type-Options to prevent MIME sniffing",
                "example": "X-Content-Type-Options: nosniff",
                "implementation_effort": "low",
            }
        )

    return recommendations


def calculate_risk_score(findings):
    """Calculate overall risk score based on findings"""
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}

    total_weight = 0
    max_possible_weight = len(findings) * 10  # Assuming all could be critical

    for finding in findings:
        severity = finding.get("severity", "INFO")
        weight = severity_weights.get(severity, 1)
        total_weight += weight

    risk_score = (
        (total_weight / max_possible_weight) * 100 if max_possible_weight > 0 else 0
    )

    # Risk classification
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "VERY LOW"

    return {
        "overall_risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "breakdown_by_severity": get_severity_breakdown(findings),
    }


def get_severity_breakdown(findings):
    """Break down findings by severity and category"""
    severity_counts = {}
    category_counts = {}

    for finding in findings:
        severity = finding.get("severity", "INFO")
        category = finding.get("category", "unknown")

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    return {"by_severity": severity_counts, "by_category": category_counts}


def prioritize_remediations(findings):
    """Prioritize remediation efforts"""
    remediation_priority = {"critical": [], "high": [], "medium": [], "low": []}

    severity_priority = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "low",
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")
        priority_level = severity_priority.get(severity, "low")

        remediation_item = {
            "id": finding.get("id"),
            "title": finding.get("id"),
            "severity": severity,
            "description": finding.get("message", ""),
            "fix": finding.get("fix_recommendations", ""),
            "effort_estimate": estimate_remediation_effort(finding),
            "business_impact": estimate_business_impact(finding),
            "category": finding.get("category", "unknown"),
        }

        remediation_priority[priority_level].append(remediation_item)

    # Sort each priority level by severity weight
    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for priority in remediation_priority:
        remediation_priority[priority].sort(
            key=lambda x: severity_weights.get(x["severity"], 0), reverse=True
        )

    return remediation_priority


def estimate_remediation_effort(finding):
    """Estimate effort required for remediation"""
    finding_id = finding.get("id", "").lower()

    if any(
        term in finding_id
        for term in ["csp", "hsts", "x-frame", "x-content-type", "permissions"]
    ):
        return {
            "level": "Low",
            "description": "Configuration change",
            "estimated_hours": 1,
        }
    elif any(term in finding_id for term in ["cache", "header", "server"]):
        return {
            "level": "Low",
            "description": "Server configuration",
            "estimated_hours": 2,
        }
    elif any(term in finding_id for term in ["information", "comment", "timestamp"]):
        return {
            "level": "Low",
            "description": "Code review and cleanup",
            "estimated_hours": 4,
        }
    else:
        return {
            "level": "Medium",
            "description": "Requires development",
            "estimated_hours": 8,
        }


def estimate_business_impact(finding):
    """Estimate business impact of the finding"""
    severity = finding.get("severity", "INFO")

    impact_map = {
        "CRITICAL": {
            "level": "High",
            "description": "Could lead to data breach or system compromise",
            "financial_impact": "Significant",
        },
        "HIGH": {
            "level": "High",
            "description": "Significant security risk",
            "financial_impact": "High",
        },
        "MEDIUM": {
            "level": "Medium",
            "description": "Moderate security concern",
            "financial_impact": "Moderate",
        },
        "LOW": {
            "level": "Low",
            "description": "Minor security issue",
            "financial_impact": "Low",
        },
        "INFO": {
            "level": "Informational",
            "description": "No immediate risk",
            "financial_impact": "None",
        },
    }

    return impact_map.get(severity, impact_map["INFO"])


def check_compliance_standards(findings):
    """Check compliance with security standards"""
    compliance = {
        "owasp_top_10": check_owasp_compliance(findings),
        "security_headers": check_headers_compliance(findings),
        "best_practices": check_best_practices(findings),
        "overall_compliance_score": calculate_compliance_score(findings),
    }

    return compliance


def check_owasp_compliance(findings):
    """Check OWASP Top 10 compliance"""
    owasp_issues = []
    owasp_categories = {
        "A01:2021-Broken Access Control": 0,
        "A02:2021-Cryptographic Failures": 0,
        "A03:2021-Injection": 0,
        "A05:2021-Security Misconfiguration": 0,
        "A07:2021-Identification and Authentication Failures": 0,
    }

    for finding in findings:
        finding_id = finding.get("id", "").lower()

        # Map findings to OWASP categories
        if any(term in finding_id for term in ["xss", "csp", "clickjacking"]):
            owasp_categories["A03:2021-Injection"] += 1
            owasp_issues.append(
                {
                    "category": "A03:2021-Injection",
                    "finding": finding.get("id"),
                    "status": "non_compliant",
                    "severity": finding.get("severity", "INFO"),
                }
            )
        elif any(term in finding_id for term in ["hsts", "ssl", "tls"]):
            owasp_categories["A02:2021-Cryptographic Failures"] += 1
            owasp_issues.append(
                {
                    "category": "A02:2021-Cryptographic Failures",
                    "finding": finding.get("id"),
                    "status": "non_compliant",
                    "severity": finding.get("severity", "INFO"),
                }
            )
        elif any(term in finding_id for term in ["cache", "header", "information"]):
            owasp_categories["A05:2021-Security Misconfiguration"] += 1
            owasp_issues.append(
                {
                    "category": "A05:2021-Security Misconfiguration",
                    "finding": finding.get("id"),
                    "status": "non_compliant",
                    "severity": finding.get("severity", "INFO"),
                }
            )

    total_issues = len(owasp_issues)
    compliance_score = max(0, 100 - (total_issues * 5))  # Deduct 5% per issue

    return {
        "compliance_score": round(compliance_score, 2),
        "issues": owasp_issues,
        "category_breakdown": owasp_categories,
    }


def check_headers_compliance(findings):
    """Check security headers compliance"""
    required_headers = ["CSP", "HSTS", "X-Frame-Options", "X-Content-Type-Options"]
    implemented_headers = []
    missing_headers = []

    for finding in findings:
        finding_id = finding.get("id", "")
        if "Content Security Policy" not in finding_id:
            implemented_headers.append("CSP")
        if "Strict-Transport-Security" not in finding_id:
            implemented_headers.append("HSTS")
        if "Clickjacking" not in finding_id:
            implemented_headers.append("X-Frame-Options")
        if "X-Content-Type-Options" not in finding_id:
            implemented_headers.append("X-Content-Type-Options")

    missing_headers = [h for h in required_headers if h not in implemented_headers]
    compliance_score = (len(implemented_headers) / len(required_headers)) * 100

    return {
        "compliance_score": round(compliance_score, 2),
        "implemented_headers": implemented_headers,
        "missing_headers": missing_headers,
        "total_headers_checked": len(required_headers),
    }


def check_best_practices(findings):
    """Check security best practices"""
    best_practices = {
        "secure_headers_configured": False,
        "information_disclosure_prevented": False,
        "cache_controls_properly_set": False,
        "modern_web_app_detected": False,
    }

    issues_count = 0

    for finding in findings:
        finding_id = finding.get("id", "")

        if "Content Security Policy" in finding_id:
            issues_count += 1
        if "Information Disclosure" in finding_id:
            issues_count += 1
            best_practices["information_disclosure_prevented"] = True
        if "Cache" in finding_id and "control" in finding_id.lower():
            issues_count += 1
            best_practices["cache_controls_properly_set"] = True
        if "Modern Web Application" in finding_id:
            best_practices["modern_web_app_detected"] = True

    best_practices["secure_headers_configured"] = issues_count == 0
    compliance_score = (
        sum(1 for practice in best_practices.values() if practice) / len(best_practices)
    ) * 100

    return {
        "compliance_score": round(compliance_score, 2),
        "best_practices_status": best_practices,
        "issues_found": issues_count,
    }


def calculate_compliance_score(findings):
    """Calculate overall compliance score"""
    owasp_score = check_owasp_compliance(findings)["compliance_score"]
    headers_score = check_headers_compliance(findings)["compliance_score"]
    best_practices_score = check_best_practices(findings)["compliance_score"]

    overall_score = (owasp_score + headers_score + best_practices_score) / 3

    return round(overall_score, 2)


def get_technical_insights(findings, results):
    """Extract technical insights from scan results"""
    insights = {
        "application_characteristics": analyze_app_characteristics(findings),
        "infrastructure_insights": analyze_infrastructure(results),
        "performance_implications": analyze_performance_impact(findings),
        "security_posture": analyze_security_posture(findings),
    }

    return insights


def analyze_app_characteristics(findings):
    """Analyze application technical characteristics"""
    characteristics = {
        "is_modern_web_app": any(
            "Modern Web Application" in f.get("id", "") for f in findings
        ),
        "uses_caching": any("Cache" in f.get("id", "") for f in findings),
        "has_info_disclosure": any(
            "Information Disclosure" in f.get("id", "") for f in findings
        ),
        "proxy_detected": any("Proxy Disclosure" in f.get("id", "") for f in findings),
        "timestamp_disclosure": any(
            "Timestamp Disclosure" in f.get("id", "") for f in findings
        ),
        "spectre_vulnerable": any("Spectre" in f.get("id", "") for f in findings),
    }

    return characteristics


def analyze_infrastructure(results):
    """Analyze infrastructure insights"""
    infrastructure = {
        "server_technology": "Unknown",
        "caching_servers_detected": False,
        "proxy_servers_detected": False,
    }

    # Extract from findings in results
    findings = results.get("findings", [])
    for finding in findings:
        finding_id = finding.get("id", "")
        if "Server Leaks Version" in finding_id:
            infrastructure["server_technology"] = "Web server version exposed"
        if "Proxy Disclosure" in finding_id:
            infrastructure["proxy_servers_detected"] = True
        if (
            "Retrieved from Cache" in finding_id
            or "Storable and Cacheable" in finding_id
        ):
            infrastructure["caching_servers_detected"] = True

    return infrastructure


def analyze_performance_impact(findings):
    """Analyze performance implications of security findings"""
    performance_impact = {
        "caching_issues": any("Cache" in f.get("id", "") for f in findings),
        "headers_overhead": any("Header" in f.get("id", "") for f in findings),
        "overall_impact": "Low",
    }

    issue_count = sum(
        1
        for f in findings
        if any(term in f.get("id", "") for term in ["Cache", "Header"])
    )

    if issue_count > 5:
        performance_impact["overall_impact"] = "High"
    elif issue_count > 2:
        performance_impact["overall_impact"] = "Medium"
    else:
        performance_impact["overall_impact"] = "Low"

    return performance_impact


def analyze_security_posture(findings):
    """Analyze overall security posture"""
    critical_issues = sum(
        1 for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]
    )
    medium_issues = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_issues = sum(1 for f in findings if f.get("severity") in ["LOW", "INFO"])

    total_issues = len(findings)

    if critical_issues > 0:
        posture = "POOR"
    elif medium_issues > 3:
        posture = "FAIR"
    elif total_issues > 10:
        posture = "MODERATE"
    elif total_issues > 5:
        posture = "GOOD"
    else:
        posture = "EXCELLENT"

    return {
        "overall_posture": posture,
        "critical_issues": critical_issues,
        "medium_issues": medium_issues,
        "low_issues": low_issues,
        "total_issues": total_issues,
    }


def analyze_vulnerability_trends(findings):
    """Analyze vulnerability trends and patterns"""
    trends = {
        "common_vulnerability_types": get_common_vulnerability_types(findings),
        "security_headers_trend": analyze_headers_trend(findings),
        "information_disclosure_trend": analyze_info_disclosure_trend(findings),
    }

    return trends


def get_common_vulnerability_types(findings):
    """Identify common vulnerability types"""
    vuln_types = {}

    for finding in findings:
        finding_id = finding.get("id", "")
        if "Header" in finding_id:
            vuln_types["security_headers"] = vuln_types.get("security_headers", 0) + 1
        elif "Information" in finding_id or "Disclosure" in finding_id:
            vuln_types["information_disclosure"] = (
                vuln_types.get("information_disclosure", 0) + 1
            )
        elif "Cache" in finding_id:
            vuln_types["caching_issues"] = vuln_types.get("caching_issues", 0) + 1
        elif "Proxy" in finding_id:
            vuln_types["infrastructure"] = vuln_types.get("infrastructure", 0) + 1
        else:
            vuln_types["other"] = vuln_types.get("other", 0) + 1

    return vuln_types


def analyze_headers_trend(findings):
    """Analyze security headers trend"""
    headers_missing = []

    for finding in findings:
        finding_id = finding.get("id", "")
        if "Content Security Policy" in finding_id:
            headers_missing.append("CSP")
        elif "Strict-Transport-Security" in finding_id:
            headers_missing.append("HSTS")
        elif "Clickjacking" in finding_id:
            headers_missing.append("X-Frame-Options")
        elif "X-Content-Type-Options" in finding_id:
            headers_missing.append("X-Content-Type-Options")

    return {
        "missing_headers": headers_missing,
        "total_missing": len(headers_missing),
        "trend": "improving" if len(headers_missing) < 3 else "needs_attention",
    }


def analyze_info_disclosure_trend(findings):
    """Analyze information disclosure trend"""
    info_issues = []

    for finding in findings:
        finding_id = finding.get("id", "")
        if "Information Disclosure" in finding_id:
            info_issues.append("suspicious_comments")
        elif "Timestamp Disclosure" in finding_id:
            info_issues.append("timestamp_exposure")
        elif "Server Leaks Version" in finding_id:
            info_issues.append("server_info")

    return {
        "disclosure_types": info_issues,
        "total_issues": len(info_issues),
        "risk_level": (
            "high"
            if len(info_issues) > 2
            else "medium" if len(info_issues) > 0 else "low"
        ),
    }


def get_comparative_metrics(scan_result, db_session):
    """Get comparative metrics with previous scans"""
    comparative = {
        "previous_scan_comparison": compare_with_previous_scans(
            scan_result, db_session
        ),
        "benchmark_metrics": get_benchmark_metrics(),
    }

    return comparative


def compare_with_previous_scans(scan_result, db_session):
    """Compare with previous scans of the same target"""
    previous_scans = (
        db_session.query(ZapScanResult)
        .filter(
            ZapScanResult.target_url == scan_result.target_url,
            ZapScanResult.id != scan_result.id,
            ZapScanResult.status == "completed",
        )
        .order_by(desc(ZapScanResult.timestamp))
        .limit(5)
        .all()
    )

    if not previous_scans:
        return {"message": "No previous scans found for comparison"}

    current_findings_count = scan_result.findings_count or 0
    previous_findings_count = previous_scans[0].findings_count or 0

    trend = (
        "improving"
        if current_findings_count < previous_findings_count
        else (
            "worsening"
            if current_findings_count > previous_findings_count
            else "stable"
        )
    )

    return {
        "trend": trend,
        "current_findings": current_findings_count,
        "previous_findings": previous_findings_count,
        "change_percentage": (
            round(
                (
                    (current_findings_count - previous_findings_count)
                    / previous_findings_count
                    * 100
                ),
                2,
            )
            if previous_findings_count > 0
            else 0
        ),
        "scans_compared": len(previous_scans),
    }


def get_benchmark_metrics():
    """Get industry benchmark metrics"""
    return {
        "average_findings_per_scan": 8.5,
        "security_headers_compliance_benchmark": 75.0,
        "risk_score_benchmark": 25.0,
        "top_vulnerability_categories": [
            "Security Headers",
            "Information Disclosure",
            "Caching Issues",
        ],
    }


def empty_dashboard_summary():
    """Return empty dashboard summary"""
    return {
        "total_scans": 0,
        "total_findings": 0,
        "average_findings_per_scan": 0,
        "average_risk_score": 0,
        "scans_trend": "no_data",
    }


def calculate_summary_metrics(scans):
    """Calculate summary metrics for dashboard"""
    total_scans = len(scans)
    total_findings = sum(scan.findings_count or 0 for scan in scans)
    avg_findings = total_findings / total_scans if total_scans > 0 else 0

    # Calculate average risk score across all scans
    risk_scores = []
    for scan in scans:
        if scan.results and scan.results.get("findings"):
            risk_score = calculate_risk_score(scan.results["findings"])
            risk_scores.append(risk_score["overall_risk_score"])

    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    # Calculate trend
    trend = "stable"
    if len(scans) >= 2:
        recent_scans = sorted(scans, key=lambda x: x.timestamp, reverse=True)[:2]
        if len(recent_scans) == 2:
            recent_findings = recent_scans[0].findings_count or 0
            previous_findings = recent_scans[1].findings_count or 0
            if recent_findings < previous_findings:
                trend = "improving"
            elif recent_findings > previous_findings:
                trend = "worsening"

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "average_findings_per_scan": round(avg_findings, 1),
        "average_risk_score": round(avg_risk, 2),
        "scans_trend": trend,
        "last_scan_date": (
            max(scan.completed_at for scan in scans).isoformat() if scans else None
        ),
    }


def analyze_scan_trends(scans):
    """Analyze scanning trends over time"""
    if len(scans) < 2:
        return {"message": "Insufficient data for trend analysis"}

    # Sort scans by date
    sorted_scans = sorted(scans, key=lambda x: x.timestamp)

    trends = {
        "findings_trend": [],
        "risk_trend": [],
        "scan_frequency": analyze_scan_frequency(scans),
    }

    for scan in sorted_scans[-10:]:  # Last 10 scans
        findings_count = scan.findings_count or 0
        risk_score = 0

        if scan.results and scan.results.get("findings"):
            risk_score = calculate_risk_score(scan.results["findings"])[
                "overall_risk_score"
            ]

        trends["findings_trend"].append(
            {
                "date": (
                    scan.completed_at.isoformat()
                    if scan.completed_at
                    else scan.timestamp.isoformat()
                ),
                "findings": findings_count,
            }
        )

        trends["risk_trend"].append(
            {
                "date": (
                    scan.completed_at.isoformat()
                    if scan.completed_at
                    else scan.timestamp.isoformat()
                ),
                "risk_score": risk_score,
            }
        )

    return trends


def analyze_scan_frequency(scans):
    """Analyze scan frequency patterns"""
    if len(scans) < 2:
        return {"average_days_between_scans": 0, "scan_frequency": "irregular"}

    sorted_scans = sorted(scans, key=lambda x: x.timestamp)
    time_diffs = []

    for i in range(1, len(sorted_scans)):
        diff = (sorted_scans[i].timestamp - sorted_scans[i - 1].timestamp).days
        time_diffs.append(diff)

    avg_days = sum(time_diffs) / len(time_diffs) if time_diffs else 0

    frequency = (
        "regular" if avg_days <= 7 else "periodic" if avg_days <= 30 else "irregular"
    )

    return {
        "average_days_between_scans": round(avg_days, 1),
        "scan_frequency": frequency,
        "total_scan_period_days": (
            sorted_scans[-1].timestamp - sorted_scans[0].timestamp
        ).days,
    }


def track_risk_evolution(scans):
    """Track risk evolution over time"""
    if len(scans) < 2:
        return {"message": "Insufficient data for risk evolution analysis"}

    sorted_scans = sorted(scans, key=lambda x: x.timestamp)

    risk_evolution = {
        "initial_risk": 0,
        "current_risk": 0,
        "improvement_percentage": 0,
        "risk_timeline": [],
    }

    # Calculate initial and current risk
    if sorted_scans[0].results and sorted_scans[0].results.get("findings"):
        risk_evolution["initial_risk"] = calculate_risk_score(
            sorted_scans[0].results["findings"]
        )["overall_risk_score"]

    if sorted_scans[-1].results and sorted_scans[-1].results.get("findings"):
        risk_evolution["current_risk"] = calculate_risk_score(
            sorted_scans[-1].results["findings"]
        )["overall_risk_score"]

    # Calculate improvement
    if risk_evolution["initial_risk"] > 0:
        improvement = (
            (risk_evolution["initial_risk"] - risk_evolution["current_risk"])
            / risk_evolution["initial_risk"]
        ) * 100
        risk_evolution["improvement_percentage"] = round(max(0, improvement), 2)

    # Build timeline
    for scan in sorted_scans[-5:]:  # Last 5 scans for timeline
        if scan.results and scan.results.get("findings"):
            risk_score = calculate_risk_score(scan.results["findings"])[
                "overall_risk_score"
            ]
            risk_evolution["risk_timeline"].append(
                {
                    "date": (
                        scan.completed_at.isoformat()
                        if scan.completed_at
                        else scan.timestamp.isoformat()
                    ),
                    "risk_score": risk_score,
                    "findings_count": scan.findings_count or 0,
                }
            )

    return risk_evolution


def compare_scans(scans):
    """Compare scans for benchmarking"""
    if len(scans) < 2:
        return {"message": "Insufficient scans for comparison"}

    # Group by target URL for comparison
    targets = {}
    for scan in scans:
        if scan.target_url not in targets:
            targets[scan.target_url] = []
        targets[scan.target_url].append(scan)

    comparison = {
        "targets_comparison": {},
        "best_performing_target": None,
        "worst_performing_target": None,
    }

    best_score = float("inf")
    worst_score = 0

    for target, target_scans in targets.items():
        avg_findings = sum(s.findings_count or 0 for s in target_scans) / len(
            target_scans
        )
        avg_risk = 0

        risk_scores = []
        for scan in target_scans:
            if scan.results and scan.results.get("findings"):
                risk_score = calculate_risk_score(scan.results["findings"])[
                    "overall_risk_score"
                ]
                risk_scores.append(risk_score)

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        comparison["targets_comparison"][target] = {
            "average_findings": round(avg_findings, 1),
            "average_risk_score": round(avg_risk, 2),
            "total_scans": len(target_scans),
        }

        # Track best and worst
        if avg_risk < best_score:
            best_score = avg_risk
            comparison["best_performing_target"] = target

        if avg_risk > worst_score:
            worst_score = avg_risk
            comparison["worst_performing_target"] = target

    return comparison


def track_remediation_progress(scans):
    """Track remediation progress over time"""
    if len(scans) < 2:
        return {"message": "Insufficient data for remediation tracking"}

    sorted_scans = sorted(scans, key=lambda x: x.timestamp)

    progress = {
        "findings_reduction": 0,
        "critical_issues_resolved": 0,
        "remediation_efficiency": 0,
    }

    # Compare first and last scan
    first_scan = sorted_scans[0]
    last_scan = sorted_scans[-1]

    progress["findings_reduction"] = (first_scan.findings_count or 0) - (
        last_scan.findings_count or 0
    )

    # Calculate critical issues resolved (simplified)
    if first_scan.results and last_scan.results:
        first_critical = sum(
            1
            for f in first_scan.results.get("findings", [])
            if f.get("severity") in ["CRITICAL", "HIGH"]
        )
        last_critical = sum(
            1
            for f in last_scan.results.get("findings", [])
            if f.get("severity") in ["CRITICAL", "HIGH"]
        )
        progress["critical_issues_resolved"] = first_critical - last_critical

    # Calculate remediation efficiency
    total_days = (last_scan.timestamp - first_scan.timestamp).days
    if total_days > 0 and progress["findings_reduction"] > 0:
        progress["remediation_efficiency"] = round(
            progress["findings_reduction"] / total_days, 2
        )

    return progress


def establish_security_baseline(scans):
    """Establish security baseline from historical data"""
    if not scans:
        return {"message": "No scan data available for baseline"}

    # Calculate baseline metrics
    total_findings = sum(scan.findings_count or 0 for scan in scans)
    avg_findings = total_findings / len(scans)

    risk_scores = []
    for scan in scans:
        if scan.results and scan.results.get("findings"):
            risk_score = calculate_risk_score(scan.results["findings"])[
                "overall_risk_score"
            ]
            risk_scores.append(risk_score)

    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    # Common vulnerability types
    common_vulns = {}
    for scan in scans:
        if scan.results:
            for finding in scan.results.get("findings", []):
                vuln_type = finding.get("id", "unknown")
                common_vulns[vuln_type] = common_vulns.get(vuln_type, 0) + 1

    top_vulns = sorted(common_vulns.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "average_findings_baseline": round(avg_findings, 1),
        "average_risk_baseline": round(avg_risk, 2),
        "total_scans_considered": len(scans),
        "top_vulnerabilities": [
            {"type": vuln[0], "count": vuln[1]} for vuln in top_vulns
        ],
        "security_maturity": assess_security_maturity(avg_risk, avg_findings),
    }


def assess_security_maturity(avg_risk, avg_findings):
    """Assess security maturity level"""
    if avg_risk < 20 and avg_findings < 5:
        return "ADVANCED"
    elif avg_risk < 40 and avg_findings < 10:
        return "INTERMEDIATE"
    elif avg_risk < 60 and avg_findings < 15:
        return "BASIC"
    else:
        return "BEGINNER"


@zap_bp.route("/scan", methods=["POST"])
def trigger_zap_scan():
    """
    Trigger a ZAP Docker scan with dedicated progress tracking.
    """
    engine = None
    db_session = None
    analysis = None

    try:
        body = request.get_json() or {}
        user_id = body.get("user_id")
        workspace_id = body.get("workspace_id")
        target = body.get("target")
        scan_type = (body.get("scan_type") or "baseline").lower()
        timeout_seconds = int(body.get("timeout_seconds") or 1800)
        fail_on_warn = bool(body.get("fail_on_warn") or False)
        use_docker = bool(body.get("use_docker", False))  # NEW: default to False

        if not all([user_id, target]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "user_id and target are required"},
                    }
                ),
                400,
            )

        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        from zap_scan_tracker import (
            clear_zap_scan_progress,
            create_zap_progress_callback,
        )

        clear_zap_scan_progress(user_id, target)

        analysis = ZapScanResult(
            target_url=target,
            scan_type=scan_type,
            user_id=user_id,
            workspace_id=workspace_id,
            status="queued",
        )
        db_session.add(analysis)
        db_session.commit()

        def run_scan_background():
            thread_engine = create_db_engine(None)
            thread_session = sessionmaker(bind=thread_engine)()

            try:
                logger.info(f"Starting ZAP background scan for {target}")

                progress_callback = create_zap_progress_callback(
                    user_id=user_id, target_url=target, scan_id=str(analysis.id)
                )

                progress_callback("initializing", 5)

                thread_session.query(ZapScanResult).filter_by(id=analysis.id).update(
                    {"status": "in_progress"}
                )
                thread_session.commit()

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                async def run():
                    from zap_scanner import ZapScannerWithProgress

                    scanner = ZapScannerWithProgress(
                        progress_callback=progress_callback
                    )
                    opts = ZapScanOptions(
                        target_url=target,
                        scan_type=scan_type,
                        timeout_seconds=timeout_seconds,
                        max_scan_duration=3600,  # 1 hour hard limi
                        progress_timeout=300,  # Kill if stuck for 5 min
                        fail_on_warn=fail_on_warn,
                        additional_args=[],
                        use_docker=use_docker,  # pass new field
                    )
                    return await scanner.run_with_progress(opts, user_id, target)

                logger.info(f"Running ZAP scan for {target}")
                result = loop.run_until_complete(run())
                loop.close()

                zap_exit_code = result.get("zap_exit_code", -1)
                scan_successful = result.get("success", False) or zap_exit_code in (
                    0,
                    1,
                    2,
                )

                logger.info(
                    f"ZAP scan completed for {target}, success: {scan_successful}"
                )

                if scan_successful:
                    data = result.get("data", {})
                    findings_count = len(data.get("findings", []))

                    # Save zap_report.html persistently
                    preferred_base_dir = os.environ.get("ZAP_REPORTS_DIR") or os.path.join(os.getcwd(), "zap_reports")
                    fallback_base_dir = "/home/steampipe/zap_reports"
                    report_filename = f"zap_report_{analysis.id}.html"
                    report_path = None

                    def try_persist_report(base_dir: str) -> Optional[str]:
                        try:
                            os.makedirs(base_dir, exist_ok=True)
                            dest_path = os.path.join(base_dir, report_filename)

                            # Prefer html_report_path from scanner result
                            temp_html_path = data.get("html_report_path")
                            if temp_html_path and os.path.exists(temp_html_path):
                                import shutil
                                shutil.copyfile(temp_html_path, dest_path)
                                return dest_path
                            else:
                                logger.info("ZAP HTML report not provided or file not found; skipping persistence")
                                return None
                        except (PermissionError, OSError) as dir_exc:
                            logger.error(f"Failed to create/write ZAP report in {base_dir}: {dir_exc}")
                            return None

                    # Try preferred location first, then fallback under the user's home
                    report_path = try_persist_report(preferred_base_dir) or try_persist_report(fallback_base_dir)

                    thread_session.query(ZapScanResult).filter_by(
                        id=analysis.id
                    ).update(
                        {
                            "status": "completed",
                            "results": data,
                            "completed_at": datetime.utcnow(),
                            "findings_count": findings_count,
                            "severity_counts": data.get(
                                "stats", {}
                            ).get(
                                "severity_counts", {}
                            ),
                            "scan_duration_seconds": (
                                int(
                                    (
                                        datetime.utcnow() - analysis.timestamp
                                    ).total_seconds()
                                )
                                if analysis.timestamp
                                else None
                            ),
                            "zap_exit_code": zap_exit_code,
                            "report_path": report_path,
                        }
                    )
                    thread_session.commit()

                    # Final progress update
                    progress_callback("completed", 100)
                    logger.info(f"ZAP scan results saved for {target}")

                else:
                    error_msg = result.get("error", {}).get(
                        "message", "ZAP scan failed"
                    )
                    logger.error(f"ZAP scan failed for {target}: {error_msg}")

                    thread_session.query(ZapScanResult).filter_by(
                        id=analysis.id
                    ).update(
                        {
                            "status": "error",
                            "error": error_msg,
                            "completed_at": datetime.utcnow(),
                            "zap_exit_code": zap_exit_code,
                        }
                    )
                    thread_session.commit()

                    progress_callback("error", 100)
                    logger.error(f"ZAP scan error saved for {target}")

            except Exception as e:
                logger.error(
                    f"ZAP background scan error for {target}: {e}", exc_info=True
                )
                try:
                    thread_session.query(ZapScanResult).filter_by(
                        id=analysis.id
                    ).update(
                        {
                            "status": "error",
                            "error": str(e),
                            "completed_at": datetime.utcnow(),
                        }
                    )
                    thread_session.commit()

                    progress_callback("error", 100)
                except Exception as db_error:
                    logger.error(f"Failed to save ZAP scan error: {db_error}")
            finally:
                try:
                    thread_session.close()
                    thread_engine.dispose()
                except Exception:
                    pass

        import threading

        t = threading.Thread(target=run_scan_background, daemon=True)
        t.start()

        return (
            jsonify(
                {
                    "success": True,
                    "message": "ZAP scan queued",
                    "scan_id": analysis.id,
                    "status": "queued",
                    "target_url": target,
                    "scan_type": scan_type,
                    "workspace_id": workspace_id,
                }
            ),
            202,
        )

    except Exception as e:
        logger.error(f"ZAP trigger error: {e}")
        if db_session and analysis:
            try:
                analysis.status = "error"
                analysis.error = str(e)
                db_session.commit()
            except Exception:
                db_session.rollback()
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/results/<int:scan_id>", methods=["GET"])
def get_zap_results(scan_id):
    """Retrieve ZAP scan results by scan ID"""
    engine = None
    db_session = None

    try:
        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        scan_result = db_session.query(ZapScanResult).filter_by(id=scan_id).first()

        if not scan_result:
            return (
                jsonify({"success": False, "error": {"message": "Scan not found"}}),
                404,
            )

        response_data = {
            "success": True,
            "scan_id": scan_result.id,
            "target_url": scan_result.target_url,
            "scan_type": scan_result.scan_type,
            "status": scan_result.status,
            "user_id": scan_result.user_id,
            "workspace_id": scan_result.workspace_id,
            "timestamp": (
                scan_result.timestamp.isoformat() if scan_result.timestamp else None
            ),
            "completed_at": (
                scan_result.completed_at.isoformat()
                if scan_result.completed_at
                else None
            ),
            "scan_duration_seconds": scan_result.scan_duration_seconds,
            "findings_count": scan_result.findings_count,
            "severity_counts": scan_result.severity_counts or {},
            "zap_exit_code": getattr(scan_result, "zap_exit_code", None),
        }

        # Include results if scan is completed
        if scan_result.status == "completed" and scan_result.results:
            response_data["results"] = scan_result.results
        elif scan_result.status == "error":
            response_data["error"] = scan_result.error

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error retrieving ZAP results: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/results/<int:scan_id>/analytics", methods=["GET"])
def get_zap_scan_analytics(scan_id):
    """Get enhanced analytics for a ZAP scan, optionally filtered by workspace ID"""
    engine = None
    db_session = None

    try:
        workspace_id = request.args.get("workspace_id")

        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(ZapScanResult).filter_by(id=scan_id)
        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)

        scan_result = query.first()

        if not scan_result:
            return (
                jsonify({"success": False, "error": {"message": "Scan not found"}}),
                404,
            )

        if not scan_result.results:
            empty_analytics = {
                "security_headers_analysis": {},
                "vulnerability_trends": {},
                "risk_assessment": {},
                "compliance_analysis": {},
                "remediation_priority": {},
                "comparative_analysis": {},
                "technical_insights": {},
            }
            return jsonify(
                {
                    "success": True,
                    "scan_id": scan_id,
                    "target_url": scan_result.target_url,
                    "analytics": empty_analytics,
                }
            ), 200

        results = scan_result.results
        findings = results.get("findings", [])

        analytics = {
            "security_headers_analysis": analyze_security_headers(findings),
            "vulnerability_trends": analyze_vulnerability_trends(findings),
            "risk_assessment": calculate_risk_score(findings),
            "compliance_analysis": check_compliance_standards(findings),
            "remediation_priority": prioritize_remediations(findings),
            "comparative_analysis": get_comparative_metrics(scan_result, db_session),
            "technical_insights": get_technical_insights(findings, results),
        }

        return jsonify(
            {
                "success": True,
                "scan_id": scan_id,
                "target_url": scan_result.target_url,
                "analytics": analytics,
            }
        )

    except Exception as e:
        logger.error(f"Error generating ZAP analytics: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/results/<int:scan_id>/download", methods=["GET"])
def download_zap_report(scan_id):
    engine = None
    db_session = None
    try:
        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        scan_result = db_session.query(ZapScanResult).filter_by(id=scan_id).first()
        if not scan_result or not scan_result.report_path:
            return jsonify({"success": False, "error": {"message": "Report not found"}}), 404

        if not os.path.exists(scan_result.report_path):
            return jsonify({"success": False, "error": {"message": "Report file is missing on server"}}), 404

        return send_file(scan_result.report_path, as_attachment=True, download_name=f"zap_report_{scan_id}.html", mimetype="text/html")
    except Exception as e:
        logger.error(f"Error downloading ZAP HTML report: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/workspace/<workspace_id>/dashboard-stats", methods=["GET"])
def get_workspace_dashboard_stats(workspace_id):
    """Get comprehensive dashboard statistics for a workspace"""
    engine = None
    db_session = None

    try:
        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        scans = (
            db_session.query(ZapScanResult)
            .filter_by(workspace_id=workspace_id, status="completed")
            .all()
        )

        if not scans:
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "message": "No completed scans found for this workspace",
                        "summary": empty_dashboard_summary(),
                    },
                }
            )

        dashboard_data = {
            "summary_metrics": calculate_summary_metrics(scans),
            "trend_analysis": analyze_scan_trends(scans),
            "risk_evolution": track_risk_evolution(scans),
            "comparative_analysis": compare_scans(scans),
            "remediation_progress": track_remediation_progress(scans),
            "security_baseline": establish_security_baseline(scans),
        }

        return jsonify(
            {"success": True, "workspace_id": workspace_id, "data": dashboard_data}
        )

    except Exception as e:
        logger.error(f"Error generating dashboard stats: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/results", methods=["GET"])
def get_zap_scan_results():
    """Get ZAP scan results with filtering"""
    engine = None
    db_session = None

    try:
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")
        target_url = request.args.get("target_url")
        scan_type = request.args.get("scan_type")
        status = request.args.get("status")
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("limit", 30))))

        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(ZapScanResult)

        if user_id:
            query = query.filter_by(user_id=user_id)
        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)
        if target_url:
            query = query.filter_by(target_url=target_url)
        if scan_type:
            query = query.filter_by(scan_type=scan_type)
        if status:
            query = query.filter_by(status=status)

        query = query.order_by(desc(ZapScanResult.timestamp))

        total_count = query.count()

        offset = (page - 1) * per_page
        results = query.offset(offset).limit(per_page).all()

        scan_results = [result.to_dict() for result in results]

        return jsonify(
            {
                "success": True,
                "data": {
                    "scans": scan_results,
                    "pagination": {
                        "current_page": page,
                        "per_page": per_page,
                        "total_items": total_count,
                        "total_pages": (total_count + per_page - 1) // per_page,
                    },
                    "filters": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "target_url": target_url,
                        "scan_type": scan_type,
                        "status": status,
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f"Error fetching ZAP scan results: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/scan/<int:scan_id>", methods=["DELETE"])
def delete_zap_scan(scan_id):
    """Delete a ZAP scan result"""
    engine = None
    db_session = None

    try:
        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        scan_result = db_session.query(ZapScanResult).filter_by(id=scan_id).first()

        if not scan_result:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "ZAP scan not found",
                            "code": "SCAN_NOT_FOUND",
                        },
                    }
                ),
                404,
            )

        db_session.delete(scan_result)
        db_session.commit()

        return jsonify({"success": True, "message": "ZAP scan deleted successfully"})

    except Exception as e:
        logger.error(f"Error deleting ZAP scan: {e}")
        if db_session:
            db_session.rollback()
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@zap_bp.route("/stats", methods=["GET"])
def get_zap_scan_stats():
    """Get ZAP scan statistics"""
    engine = None
    db_session = None

    try:
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")

        engine = create_db_engine(None)
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(ZapScanResult)

        if user_id:
            query = query.filter_by(user_id=user_id)
        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)

        total_scans = query.count()
        completed_scans = query.filter_by(status="completed").count()
        error_scans = query.filter_by(status="error").count()
        pending_scans = query.filter_by(status="pending").count()
        in_progress_scans = query.filter_by(status="in_progress").count()

        scan_type_stats = {}
        scan_types = (
            db_session.query(
                ZapScanResult.scan_type, func.count(ZapScanResult.id)
            )
            .group_by(ZapScanResult.scan_type)
            .all()
        )
        for scan_type, count in scan_types:
            scan_type_stats[scan_type] = count

        recent_scans = query.order_by(desc(ZapScanResult.timestamp)).limit(10).all()
        recent_scans_data = [scan.to_dict() for scan in recent_scans]

        return jsonify(
            {
                "success": True,
                "data": {
                    "total_scans": total_scans,
                    "status_breakdown": {
                        "completed": completed_scans,
                        "error": error_scans,
                        "pending": pending_scans,
                        "in_progress": in_progress_scans,
                    },
                    "scan_type_breakdown": scan_type_stats,
                    "recent_scans": recent_scans_data,
                    "filters": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f"Error fetching ZAP scan stats: {e}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()