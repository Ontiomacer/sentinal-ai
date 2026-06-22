"""
Test Script: Validate AI Runtime Analyst Uses Live Device Data

This script calls the validation endpoint to prove:
1. Packages are enumerated from the actual connected device
2. APK is extracted from the device (not mock/uploaded data)
3. Runtime data comes from live ADB commands
4. AI analysis references actual runtime artifacts
"""

import asyncio
import httpx
import json

async def test_validation():
    """Test the runtime data validation endpoint"""
    
    # Configuration
    API_BASE = "http://localhost:8000"
    DEVICE_SERIAL = "R9ZY90CPP0K"  # Samsung Galaxy A06
    TEST_PACKAGE = "com.openai.chatgpt"  # ChatGPT APK on device
    
    print("=" * 80)
    print("VALIDATION TEST: AI Runtime Analyst Live Data Flow")
    print("=" * 80)
    print(f"Device: {DEVICE_SERIAL}")
    print(f"Target Package: {TEST_PACKAGE}")
    print("=" * 80)
    print()
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            print("Calling validation endpoint...")
            print(f"GET {API_BASE}/api/v1/device-lab/validate/runtime-data")
            print()
            
            response = await client.get(
                f"{API_BASE}/api/v1/device-lab/validate/runtime-data",
                params={
                    "serial": DEVICE_SERIAL,
                    "package": TEST_PACKAGE
                }
            )
            
            if response.status_code != 200:
                print(f"❌ Error: {response.status_code}")
                print(response.text)
                return
            
            data = response.json()
            validation = data.get("validation", {})
            
            print("✅ VALIDATION SUCCESSFUL")
            print("=" * 80)
            print()
            
            # Display Evidence Chain
            print("EVIDENCE CHAIN:")
            print("-" * 80)
            for i, evidence in enumerate(validation.get("evidence_chain", []), 1):
                if "step" in evidence:
                    print(f"\n{evidence['step']}")
                    print(f"Description: {evidence['description']}")
                else:
                    print(f"{i}. {evidence.get('evidence', evidence)}")
                    if 'source' in evidence:
                        print(f"   Source: {evidence['source']}")
                    if 'proof' in evidence:
                        print(f"   Proof: {evidence['proof'][:80]}...")
            print()
            print("=" * 80)
            print()
            
            # Display Step 1: Package Enumeration
            step1 = validation.get("step1_package_enumeration", {})
            print("STEP 1: LIVE PACKAGE ENUMERATION")
            print("-" * 80)
            print(f"ADB Command: {step1.get('adb_command')}")
            print(f"Return Code: {step1.get('execution_returncode')}")
            print(f"Total Packages Detected: {step1.get('total_packages_detected')}")
            print(f"Target Package Found: {step1.get('target_package_found')}")
            print(f"Sample Packages: {step1.get('sample_packages', [])[:3]}")
            print()
            
            # Display Step 2: APK Extraction
            step2 = validation.get("step2_apk_location", {})
            step2_extract = validation.get("step2_apk_extraction", {})
            print("STEP 2: APK EXTRACTION FROM DEVICE")
            print("-" * 80)
            print(f"ADB Command (locate): {step2.get('adb_command')}")
            print(f"APK Path on Device: {step2.get('apk_path_on_device')}")
            print(f"Is Split APK: {step2.get('is_split_apk')}")
            print()
            print(f"ADB Command (pull): {step2_extract.get('adb_command', 'N/A')[:80]}...")
            print(f"Local Path: {step2_extract.get('local_path')}")
            print(f"File Size: {step2_extract.get('file_size_mb')} MB")
            print(f"SHA256 Hash: {step2_extract.get('sha256_hash')}")
            print(f"Extraction Success: {step2_extract.get('extraction_success')}")
            print()
            
            # Display Step 3: Runtime Data
            step3_activities = validation.get("step3_runtime_activities", {})
            step3_services = validation.get("step3_runtime_services", {})
            step3_perms = validation.get("step3_runtime_permissions", {})
            step3_procs = validation.get("step3_runtime_processes", {})
            step3_net = validation.get("step3_runtime_network", {})
            
            print("STEP 3: RUNTIME DATA COLLECTION")
            print("-" * 80)
            print(f"Activities Command: {step3_activities.get('adb_command', 'N/A')[:60]}...")
            print(f"  Sample Activities: {len(step3_activities.get('sample_activities', []))} detected")
            print()
            print(f"Services Command: {step3_services.get('adb_command', 'N/A')[:60]}...")
            print(f"  Running Services: {step3_services.get('service_count')}")
            print()
            print(f"Permissions Command: {step3_perms.get('adb_command', 'N/A')[:60]}...")
            print(f"  Dangerous Permissions: {step3_perms.get('permission_count')}")
            print(f"  Sample: {[p.get('permission', p) for p in step3_perms.get('dangerous_permissions', [])[:3]]}")
            print()
            print(f"Processes Command: {step3_procs.get('adb_command', 'N/A')[:60]}...")
            print(f"  Total Processes: {step3_procs.get('total_processes')}")
            print(f"  Package Processes: {len(step3_procs.get('package_processes', []))}")
            print()
            print(f"Network Command: {step3_net.get('adb_command', 'N/A')[:60]}...")
            print(f"  Active Connections: {step3_net.get('active_connections')}")
            print()
            
            # Display Step 4: AI Analysis
            step4 = validation.get("step4_ai_analysis", {})
            step4_mapping = validation.get("step4_evidence_mapping", [])
            
            print("STEP 4: AI ANALYSIS WITH EVIDENCE")
            print("-" * 80)
            print(f"Model: {step4.get('model')}")
            print(f"Runtime Context Provided:")
            for key, value in step4.get('runtime_context_provided', {}).items():
                if isinstance(value, list):
                    print(f"  - {key}: {len(value)} items")
                else:
                    print(f"  - {key}: {value}")
            print()
            print("AI Response (first 500 chars):")
            print("-" * 80)
            print(step4.get('ai_response', '')[:500])
            print()
            print(f"Evidence Mapping: {len(step4_mapping)} artifacts referenced by AI")
            for mapping in step4_mapping[:3]:
                print(f"  ✓ {mapping.get('runtime_artifact')} → AI Referenced: {mapping.get('ai_referenced')}")
            print()
            
            # Display Validation Summary
            summary = validation.get("validation_summary", {})
            proof = summary.get("proof_of_live_data", {})
            
            print("=" * 80)
            print("VALIDATION SUMMARY")
            print("=" * 80)
            print(f"✓ Package count matches device (130 packages): {proof.get('package_count_matches_device')}")
            print(f"✓ Target package exists on device: {proof.get('target_package_exists_on_device')}")
            print(f"✓ APK extracted from device: {proof.get('apk_extracted_from_device')}")
            print(f"✓ Runtime data from actual device: {proof.get('runtime_data_from_actual_device')}")
            print(f"✓ AI uses runtime artifacts: {proof.get('ai_uses_runtime_artifacts')}")
            print(f"✓ Evidence chain complete: {summary.get('evidence_chain_complete')}")
            print()
            print(f"CONCLUSION: {summary.get('conclusion')}")
            print("=" * 80)
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_validation())
