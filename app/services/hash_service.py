import hashlib
from pathlib import Path


class HashService:
    """Service for generating file hashes."""
    
    @staticmethod
    async def calculate_sha256(file_path: Path) -> str:
        """
        Calculate SHA256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA256 hash as hexadecimal string
        """
        sha256_hash = hashlib.sha256()
        
        # Read file in chunks to handle large files efficiently
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
