import zipfile
from pathlib import Path
from typing import Tuple


class APKValidator:
    """Service for validating APK files."""
    
    @staticmethod
    def validate_apk(file_path: Path) -> Tuple[bool, str]:
        """
        Validate if the uploaded file is a valid APK.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check file extension
        if file_path.suffix.lower() != '.apk':
            return False, "File must have .apk extension"
        
        # Check if file exists
        if not file_path.exists():
            return False, "File does not exist"
        
        # Check if file is not empty
        if file_path.stat().st_size == 0:
            return False, "File is empty"
        
        # Validate APK structure (APK is a ZIP file)
        try:
            with zipfile.ZipFile(file_path, 'r') as apk_zip:
                # Check for AndroidManifest.xml (required in all APKs)
                if 'AndroidManifest.xml' not in apk_zip.namelist():
                    return False, "Invalid APK: AndroidManifest.xml not found"
                
                # Check for classes.dex (contains compiled code)
                dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                if not dex_files:
                    return False, "Invalid APK: No .dex files found"
                
        except zipfile.BadZipFile:
            return False, "Invalid APK: Not a valid ZIP file"
        except Exception as e:
            return False, f"Invalid APK: {str(e)}"
        
        return True, "Valid APK"
