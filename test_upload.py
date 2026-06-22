"""
Simple test script to verify the upload endpoint.
This creates a minimal valid APK file for testing.
"""
import requests
import zipfile
import io
import os


def create_minimal_apk():
    """Create a minimal valid APK file for testing."""
    # Create an in-memory ZIP file
    apk_buffer = io.BytesIO()
    
    with zipfile.ZipFile(apk_buffer, 'w', zipfile.ZIP_DEFLATED) as apk_zip:
        # Add AndroidManifest.xml (minimal valid manifest)
        manifest_content = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application android:label="Test App">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
        apk_zip.writestr('AndroidManifest.xml', manifest_content)
        
        # Add a minimal classes.dex file (just header bytes)
        # This is a minimal DEX header that will pass basic validation
        dex_header = b'dex\n035\x00' + b'\x00' * 90
        apk_zip.writestr('classes.dex', dex_header)
    
    apk_buffer.seek(0)
    return apk_buffer


def test_upload():
    """Test the upload endpoint."""
    base_url = "http://localhost:8000"
    
    # Check if server is running
    try:
        response = requests.get(f"{base_url}/health")
        print(f"✓ Server is running: {response.json()}")
    except requests.exceptions.ConnectionError:
        print("✗ Server is not running. Start it with: uvicorn app.main:app --reload")
        return
    
    # Create test APK
    print("\nCreating test APK...")
    apk_file = create_minimal_apk()
    
    # Upload APK
    print("Uploading APK...")
    files = {'file': ('test_app.apk', apk_file, 'application/vnd.android.package-archive')}
    response = requests.post(f"{base_url}/api/v1/upload", files=files)
    
    if response.status_code == 201:
        data = response.json()
        print(f"\n✓ Upload successful!")
        print(f"  Scan ID: {data['scan_id']}")
        print(f"  SHA256: {data['sha256']}")
        print(f"  Filename: {data['filename']}")
        print(f"  File Size: {data['file_size']} bytes")
        print(f"  Status: {data['status']}")
        print(f"  Created At: {data['created_at']}")
        
        # Test retrieving the scan
        scan_id = data['scan_id']
        print(f"\nRetrieving scan {scan_id}...")
        response = requests.get(f"{base_url}/api/v1/scan/{scan_id}")
        
        if response.status_code == 200:
            print("✓ Scan retrieved successfully!")
        else:
            print(f"✗ Failed to retrieve scan: {response.status_code}")
            print(response.text)
        
        # Test duplicate upload
        print("\nTesting duplicate upload...")
        apk_file.seek(0)
        files = {'file': ('test_app.apk', apk_file, 'application/vnd.android.package-archive')}
        response = requests.post(f"{base_url}/api/v1/upload", files=files)
        
        if response.status_code == 201:
            dup_data = response.json()
            if dup_data['scan_id'] == data['scan_id']:
                print("✓ Duplicate detection working - returned existing scan")
            else:
                print("✗ Duplicate detection failed - created new scan")
        
    else:
        print(f"\n✗ Upload failed: {response.status_code}")
        print(response.text)


if __name__ == "__main__":
    test_upload()
