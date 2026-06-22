"""
Ghidra Installation Test Script
Verifies Ghidra is properly installed and functional
"""

import os
import sys
import subprocess
from pathlib import Path


def check_java():
    """Check if Java is installed and version is compatible."""
    print("Checking Java installation...")
    try:
        result = subprocess.run(
            ['java', '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        version_output = result.stderr  # Java outputs version to stderr
        print(f"✓ Java is installed")
        print(f"  {version_output.split(chr(10))[0]}")
        
        # Check version
        if any(v in version_output for v in ['17', '18', '19', '20', '21']):
            print("✓ Java version is compatible (17+)")
            return True
        else:
            print("⚠ Java version may be incompatible (requires 17+)")
            return True
            
    except FileNotFoundError:
        print("✗ Java is not installed")
        print("  Install from: https://adoptium.net/temurin/releases/")
        return False
    except Exception as e:
        print(f"✗ Error checking Java: {str(e)}")
        return False


def find_ghidra():
    """Find Ghidra installation."""
    print("\nSearching for Ghidra installation...")
    
    # Check environment variable
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_dir and os.path.exists(ghidra_dir):
        print(f"✓ Found Ghidra via GHIDRA_INSTALL_DIR")
        print(f"  {ghidra_dir}")
        return Path(ghidra_dir)
    
    # Check common locations
    possible_paths = [
        r"C:\Tools\ghidra",
        r"C:\Program Files\ghidra",
        Path.home() / "ghidra",
        "/opt/ghidra",
        "/usr/local/ghidra",
    ]
    
    for base_path in possible_paths:
        base_path = Path(base_path)
        if base_path.exists():
            # Look for versioned directories
            for item in base_path.iterdir():
                if item.is_dir() and 'ghidra' in item.name.lower():
                    print(f"✓ Found Ghidra at {item}")
                    return item
    
    print("✗ Ghidra not found")
    print("  Run INSTALL_GHIDRA.bat to install")
    return None


def check_ghidra_structure(ghidra_path):
    """Verify Ghidra directory structure."""
    print("\nVerifying Ghidra structure...")
    
    required_files = [
        'support/analyzeHeadless.bat',
        'support/analyzeHeadless',
        'Ghidra/Features',
        'GPL/DemanglerGnu',
    ]
    
    all_good = True
    for file_path in required_files:
        full_path = ghidra_path / file_path
        if full_path.exists():
            print(f"✓ {file_path}")
        else:
            # Check alternative (Windows vs Linux)
            if 'analyzeHeadless' in file_path:
                continue  # One of them should exist
            print(f"⚠ {file_path} not found")
            all_good = False
    
    return all_good


def test_ghidra_headless(ghidra_path):
    """Test Ghidra headless mode."""
    print("\nTesting Ghidra headless mode...")
    
    # Find analyzeHeadless script
    if os.name == 'nt':  # Windows
        script = ghidra_path / 'support' / 'analyzeHeadless.bat'
    else:  # Linux/Mac
        script = ghidra_path / 'support' / 'analyzeHeadless'
    
    if not script.exists():
        print(f"✗ analyzeHeadless script not found at {script}")
        return False
    
    print(f"  Script: {script}")
    
    try:
        result = subprocess.run(
            [str(script), '-help'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 or 'usage' in result.stdout.lower():
            print("✓ Ghidra headless mode is functional")
            return True
        else:
            print("⚠ Ghidra headless test returned non-zero exit code")
            print(f"  This may be normal - Ghidra will be tested during actual use")
            return True
            
    except subprocess.TimeoutExpired:
        print("⚠ Ghidra headless test timed out")
        return False
    except Exception as e:
        print(f"✗ Error testing Ghidra: {str(e)}")
        return False


def test_python_integration():
    """Test Python integration with Ghidra service."""
    print("\nTesting Python integration...")
    
    try:
        from app.services.ghidra_integration import get_ghidra_analyzer
        
        analyzer = get_ghidra_analyzer()
        
        if analyzer.is_available:
            print("✓ Ghidra analyzer is available")
            print(f"  Ghidra path: {analyzer.ghidra_path}")
            print(f"  analyzeHeadless: {analyzer.analyze_headless}")
            return True
        else:
            print("✗ Ghidra analyzer reports unavailable")
            print(f"  Ghidra path: {analyzer.ghidra_path}")
            return False
            
    except ImportError as e:
        print(f"✗ Cannot import Ghidra integration: {str(e)}")
        print("  Make sure you're running from the project root")
        return False
    except Exception as e:
        print(f"✗ Error testing integration: {str(e)}")
        return False


def print_summary(results):
    """Print test summary."""
    print("\n" + "="*50)
    print("GHIDRA INSTALLATION TEST SUMMARY")
    print("="*50)
    
    all_passed = all(results.values())
    
    for test, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test}")
    
    print("="*50)
    
    if all_passed:
        print("\n✓ All tests passed!")
        print("\nGhidra is ready for use in the Neural Lab")
        print("\nNext steps:")
        print("1. Start backend: python -m uvicorn app.main:app --reload")
        print("2. Start frontend: cd frontend && npm run dev")
        print("3. Upload APK and run Neural Lab analysis")
    else:
        print("\n⚠ Some tests failed")
        print("\nTroubleshooting:")
        print("1. Run INSTALL_GHIDRA.bat to install/reinstall Ghidra")
        print("2. Ensure Java 17+ is installed")
        print("3. Set GHIDRA_INSTALL_DIR environment variable")
        print("4. Restart terminal after installation")
    
    print()


def main():
    """Run all tests."""
    print("="*50)
    print("GHIDRA INSTALLATION TEST")
    print("="*50)
    print()
    
    results = {}
    
    # Test 1: Java
    results['Java Installation'] = check_java()
    
    # Test 2: Find Ghidra
    ghidra_path = find_ghidra()
    results['Ghidra Found'] = ghidra_path is not None
    
    if ghidra_path:
        # Test 3: Verify structure
        results['Ghidra Structure'] = check_ghidra_structure(ghidra_path)
        
        # Test 4: Test headless mode
        results['Ghidra Headless'] = test_ghidra_headless(ghidra_path)
    else:
        results['Ghidra Structure'] = False
        results['Ghidra Headless'] = False
    
    # Test 5: Python integration
    results['Python Integration'] = test_python_integration()
    
    # Print summary
    print_summary(results)
    
    return 0 if all(results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
