"""
Test script for risk scoring system.
This script demonstrates the risk assessment capabilities.
"""
import requests
import json
import sys


def print_risk_assessment(risk_assessment):
    """Print formatted risk assessment."""
    print("\n" + "="*60)
    print("RISK ASSESSMENT")
    print("="*60)
    
    # Risk score and severity
    score = risk_assessment.get('risk_score', 0)
    severity = risk_assessment.get('severity', 'UNKNOWN')
    
    # Color coding for severity
    severity_colors = {
        'LOW': '🟢',
        'MEDIUM': '🟡',
        'HIGH': '🟠',
        'CRITICAL': '🔴'
    }
    
    icon = severity_colors.get(severity, '⚪')
    
    print(f"\n{icon} RISK SCORE: {score}/100")
    print(f"{icon} SEVERITY: {severity}")
    
    # Summary
    summary = risk_assessment.get('summary', '')
    if summary:
        print(f"\n📋 SUMMARY:")
        print(f"  {summary}")
    
    # Score breakdown
    breakdown = risk_assessment.get('score_breakdown', {})
    if breakdown:
        print(f"\n📊 SCORE BREAKDOWN:")
        for category, points in breakdown.items():
            if points > 0:
                print(f"  • {category.replace('_', ' ').title()}: +{points} points")
    
    # Findings
    findings = risk_assessment.get('findings', [])
    if findings:
        print(f"\n⚠️  SECURITY FINDINGS ({len(findings)} total):")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding}")
    
    print("\n" + "="*60)


def test_risk_scoring():
    """Test the risk scoring functionality."""
    base_url = "http://localhost:8000"
    
    # Check if server is running
    try:
        response = requests.get(f"{base_url}/health")
        print(f"✓ Server is running: {response.json()}")
    except requests.exceptions.ConnectionError:
        print("✗ Server is not running. Start it with: python -m uvicorn app.main:app --reload")
        return
    
    # Check if user provided an APK file
    if len(sys.argv) < 2:
        print("\n" + "="*60)
        print("RISK SCORING TEST")
        print("="*60)
        print("\nUsage: python test_risk_scoring.py <path_to_apk_file>")
        print("\nExample: python test_risk_scoring.py sample.apk")
        print("\nNote: You need a real APK file to test risk scoring.")
        print("\nThe risk scorer evaluates:")
        print("  • High-risk permissions (SMS, accessibility, overlays)")
        print("  • Suspicious permission combinations")
        print("  • Exported components")
        print("  • Native code presence")
        print("  • SDK version targeting")
        print("  • Signing status")
        print("\nRisk Levels:")
        print("  🟢 LOW (0-29): Minimal security concerns")
        print("  🟡 MEDIUM (30-49): Some security concerns")
        print("  🟠 HIGH (50-69): Multiple concerning indicators")
        print("  🔴 CRITICAL (70-100): Highly suspicious behavior")
        return
    
    apk_path = sys.argv[1]
    
    # Upload APK
    print(f"\nUploading APK: {apk_path}")
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (apk_path, f, 'application/vnd.android.package-archive')}
            response = requests.post(f"{base_url}/api/v1/upload", files=files)
    except FileNotFoundError:
        print(f"✗ File not found: {apk_path}")
        return
    
    if response.status_code == 201:
        data = response.json()
        print(f"\n✓ Upload successful!")
        print(f"  Scan ID: {data['scan_id']}")
        print(f"  SHA256: {data['sha256']}")
        print(f"  Status: {data['status']}")
        
        # Display analysis results
        if data.get('analysis_result'):
            analysis = data['analysis_result']
            
            if analysis.get('analysis_failed'):
                print(f"\n✗ Analysis failed: {analysis.get('error')}")
            else:
                # Basic Info
                print(f"\n📱 APK INFORMATION")
                print(f"  Package: {analysis.get('package_name')}")
                print(f"  App Name: {analysis.get('app_name')}")
                print(f"  Version: {analysis.get('version_name')}")
                
                # Permissions summary
                permissions = analysis.get('permissions', [])
                dangerous = [p for p in permissions if p.get('category') == 'dangerous']
                print(f"\n🔐 PERMISSIONS")
                print(f"  Total: {len(permissions)}")
                print(f"  Dangerous: {len(dangerous)}")
                
                # Components summary
                activities = analysis.get('activities', [])
                services = analysis.get('services', [])
                receivers = analysis.get('receivers', [])
                print(f"\n📦 COMPONENTS")
                print(f"  Activities: {len(activities)}")
                print(f"  Services: {len(services)}")
                print(f"  Receivers: {len(receivers)}")
                
                # Risk Assessment
                risk_assessment = analysis.get('risk_assessment')
                if risk_assessment:
                    print_risk_assessment(risk_assessment)
                    
                    # Save detailed results
                    output_file = f"risk_assessment_{data['scan_id']}.json"
                    with open(output_file, 'w') as f:
                        json.dump({
                            'scan_id': data['scan_id'],
                            'package_name': analysis.get('package_name'),
                            'risk_assessment': risk_assessment,
                            'permissions': permissions,
                            'components': {
                                'activities': len(activities),
                                'services': len(services),
                                'receivers': len(receivers)
                            }
                        }, f, indent=2)
                    print(f"\n💾 Detailed assessment saved to: {output_file}")
                else:
                    print("\n⚠️  No risk assessment available")
        
        # Test retrieval endpoint
        print(f"\n\nTesting GET /api/v1/scan/{data['scan_id']}...")
        response = requests.get(f"{base_url}/api/v1/scan/{data['scan_id']}")
        
        if response.status_code == 200:
            print("✓ Scan retrieval successful!")
        else:
            print(f"✗ Failed to retrieve scan: {response.status_code}")
            
    else:
        print(f"\n✗ Upload failed: {response.status_code}")
        print(response.text)


def test_scoring_logic():
    """Test the scoring logic with mock data."""
    print("\n" + "="*60)
    print("TESTING RISK SCORING LOGIC")
    print("="*60)
    
    from app.services.risk_scorer import RiskScorer
    
    # Test case 1: Low risk app
    print("\n📱 Test Case 1: Low Risk App")
    low_risk = {
        "package_name": "com.example.safe",
        "permissions": [
            {"name": "android.permission.INTERNET", "category": "network"},
            {"name": "android.permission.ACCESS_NETWORK_STATE", "category": "network"}
        ],
        "activities": [{"name": "MainActivity", "is_exported": False}],
        "services": [],
        "receivers": [],
        "providers": [],
        "files": {"has_native_code": False},
        "target_sdk_version": "33",
        "is_signed": True,
        "is_valid_apk": True
    }
    
    result = RiskScorer.calculate_risk_score(low_risk)
    print(f"  Score: {result['risk_score']}/100")
    print(f"  Severity: {result['severity']}")
    print(f"  Findings: {len(result['findings'])}")
    
    # Test case 2: High risk app
    print("\n📱 Test Case 2: High Risk App")
    high_risk = {
        "package_name": "com.suspicious.app",
        "permissions": [
            {"name": "android.permission.READ_SMS", "category": "dangerous"},
            {"name": "android.permission.SEND_SMS", "category": "dangerous"},
            {"name": "android.permission.INTERNET", "category": "network"},
            {"name": "android.permission.SYSTEM_ALERT_WINDOW", "category": "system"},
            {"name": "android.permission.BIND_ACCESSIBILITY_SERVICE", "category": "system"},
            {"name": "android.permission.READ_CONTACTS", "category": "dangerous"},
            {"name": "android.permission.RECORD_AUDIO", "category": "dangerous"},
        ],
        "activities": [{"name": "MainActivity", "is_exported": True}],
        "services": [
            {"name": "BackgroundService", "is_exported": True},
            {"name": "AccessibilityService", "is_exported": True}
        ],
        "receivers": [{"name": f"Receiver{i}", "is_exported": True} for i in range(8)],
        "providers": [{"name": "DataProvider", "is_exported": True}],
        "files": {"has_native_code": True, "so_files": ["lib1.so", "lib2.so", "lib3.so"]},
        "target_sdk_version": "19",
        "is_signed": True,
        "is_valid_apk": True
    }
    
    result = RiskScorer.calculate_risk_score(high_risk)
    print(f"  Score: {result['risk_score']}/100")
    print(f"  Severity: {result['severity']}")
    print(f"  Findings: {len(result['findings'])}")
    for finding in result['findings'][:5]:
        print(f"    • {finding}")
    if len(result['findings']) > 5:
        print(f"    ... and {len(result['findings']) - 5} more")
    
    print("\n✓ Scoring logic test complete!")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test-logic":
        test_scoring_logic()
    else:
        test_risk_scoring()
