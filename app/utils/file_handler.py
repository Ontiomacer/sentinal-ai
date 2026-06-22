import shutil
from pathlib import Path
from fastapi import UploadFile
from typing import Tuple


class FileHandler:
    """Utility class for handling file operations."""
    
    @staticmethod
    async def save_upload_file(upload_file: UploadFile, destination: Path) -> int:
        """
        Save an uploaded file to disk.
        
        Args:
            upload_file: FastAPI UploadFile object
            destination: Destination path
            
        Returns:
            File size in bytes
        """
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        file_size = 0
        with open(destination, "wb") as buffer:
            while chunk := await upload_file.read(8192):
                buffer.write(chunk)
                file_size += len(chunk)
        
        return file_size
    
    @staticmethod
    def move_file(source: Path, destination: Path) -> None:
        """
        Move a file from source to destination.
        
        Args:
            source: Source file path
            destination: Destination file path
        """
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
    
    @staticmethod
    def delete_file(file_path: Path) -> None:
        """
        Delete a file if it exists.
        
        Args:
            file_path: Path to file to delete
        """
        if file_path.exists():
            file_path.unlink()
    
    @staticmethod
    def generate_storage_path(storage_dir: Path, sha256: str, filename: str) -> Path:
        """
        Generate a storage path based on SHA256 hash.
        Uses first 2 characters of hash for directory structure.
        
        Args:
            storage_dir: Base storage directory
            sha256: SHA256 hash
            filename: Original filename
            
        Returns:
            Path for storing the file
        """
        # Sanitize filename to prevent path traversal
        safe_filename = Path(filename).name
        # Use first 2 chars of hash for subdirectory
        subdir = sha256[:2]
        return storage_dir / subdir / f"{sha256}_{safe_filename}"
