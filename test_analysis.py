"""
Test script for APK static analysis.
This script tests the analysis endpoint with detailed output.
"""
import requests
import json
import sys


def test_analysis():
    """Test the analysis functionality."""
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
        print("\nUsage: python test_analysis.py <path_to_apk_file>")
        print("\nExample: python test_analysis.py sample.apk")
        print("\nNote: You need a real APK file to test the analysis.")
        print("You can download sample APKs from:")
        print("  - https://apkpure.com")
        print("  - https://f-droid.org")
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
            print("\n" + "="*60)
            print("STATIC ANALYSIS RESULTS")
            print("="*60)
            
            analysis = data['analysis_result']
            
            if analysis.get('analysis_failed'):
                print(f"\n✗ Analysis failed: {analysis.get('error')}")
            else:
                # Basic Info
                print(f"\n📱 BASIC INFORMATION")
                print(f"  Package Name: {analysis.get('package_name')}")
                print(f"  App Name: {analysis.get('app_name')}")
                print(f"  Version: {analysis.get('version_name')} (code: {analysis.get('version_code')})")
                print(f"  Min SDK: {analysis.get('min_sdk_version')}")
                print(f"  Target SDK: {analysis.get('target_sdk_version')}")
                print(f"  Signed: {analysis.get('is_signed')}")
                print(f"  Valid APK: {analysis.get('is_valid_apk')}")
                print(f"  Main Activity: {analysis.get('main_activity')}")
                
                # Permissions
                permissions = analysis.get('permissions', [])
                print(f"\n🔐 PERMISSIONS ({len(permissions)} total)")
                
                # Group by category
                dangerous = [p for p in permissions if p.get('category') == 'dangerous']
                network = [p for p in permissions if p.get('category') == 'network']
                system = [p for p in permissions if p.get('category') == 'system']
                normal = [p for p in permissions if p.get('category') == 'normal']
                
                if dangerous:
                    print(f"\n  ⚠️  Dangerous Permissions ({len(dangerous)}):")
                    for perm in dangerous[:5]:  # Show first 5
                        print(f"    - {perm['name']}")
                    if len(dangerous) > 5:
                        print(f"    ... and {len(dangerous) - 5} more")
                
                if network:
                    print(f"\n  🌐 Network Permissions ({len(network)}):")
                    for perm in network[:3]:
                        print(f"    - {perm['name']}")
                
                if system:
                    print(f"\n  ⚙️  System Permissions ({len(system)}):")
                    for perm in system[:3]:
                        print(f"    - {perm['name']}")
                
                # Components
                activities = analysis.get('activities', [])
                services = analysis.get('services', [])
                receivers = analysis.get('receivers', [])
                providers = analysis.get('providers', [])
                
                print(f"\n📦 COMPONENTS")
                print(f"  Activities: {len(activities)}")
                print(f"  Services: {len(services)}")
                print(f"  Receivers: {len(receivers)}")
                print(f"  Providers: {len(providers)}")
                
                # Show exported components (potential security concern)
                exported_activities = [a for a in activities if a.get('is_exported')]
                exported_services = [s for s in services if s.get('is_exported')]
                exported_receivers = [r for r in receivers if r.get('is_exported')]
                
                if exported_activities or exported_services or exported_receivers:
                    print(f"\n  ⚠️  Exported Components:")
                    if exported_activities:
                        print(f"    - {len(exported_activities)} exported activities")
                    if exported_services:
                        print(f"    - {len(exported_services)} exported services")
                    if exported_receivers:
                        print(f"    - {len(exported_receivers)} exported receivers")
                
                # File Info
                files = analysis.get('files', {})
                print(f"\n📁 FILE INFORMATION")
                print(f"  Total Files: {files.get('total_files')}")
                print(f"  DEX Files: {len(files.get('dex_files', []))}")
                print(f"  Native Libraries: {len(files.get('so_files', []))}")
                print(f"  Has Native Code: {files.get('has_native_code')}")
                print(f"  Has Assets: {files.get('has_assets')}")
                
                # Libraries
                libraries = analysis.get('libraries', [])
                if libraries:
                    print(f"\n📚 LIBRARIES ({len(libraries)})")
                    for lib in libraries[:5]:
                        print(f"  - {lib}")
                    if len(libraries) > 5:
                        print(f"  ... and {len(libraries) - 5} more")
                
                print("\n" + "="*60)
                
                # Save full results to file
                output_file = f"analysis_{data['scan_id']}.json"
                with open(output_file, 'w') as f:
                    json.dump(analysis, f, indent=2)
                print(f"\n💾 Full analysis saved to: {output_file}")
        
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


if __name__ == "__main__":
    test_analysis()
