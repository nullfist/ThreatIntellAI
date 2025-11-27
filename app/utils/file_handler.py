import os
import uuid
from fastapi import UploadFile, HTTPException
import aiofiles
from typing import List

class FileHandler:
    UPLOAD_DIR = "app/storage/uploaded_logs"
    
    @staticmethod
    async def save_uploaded_file(file: UploadFile) -> str:
        """Save uploaded file and return file path"""
        try:
            # Create upload directory if it doesn't exist
            os.makedirs(FileHandler.UPLOAD_DIR, exist_ok=True)
            
            # Generate unique filename
            file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'log'
            filename = f"{uuid.uuid4()}.{file_extension}"
            file_path = os.path.join(FileHandler.UPLOAD_DIR, filename)
            
            # Save file
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            return file_path
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")
    
    @staticmethod
    async def read_file_lines(file_path: str) -> List[str]:
        """Read file and return lines"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                return content.splitlines()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"File reading failed: {str(e)}")
    
    @staticmethod
    def cleanup_file(file_path: str):
        """Clean up uploaded file after processing"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass  # Silent cleanup