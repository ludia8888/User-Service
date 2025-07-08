"""User Service 실행 스크립트 - 포트 8001에서 실행"""

import os
import sys

# src 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# 환경 변수 설정
os.environ['PORT'] = '8101'

# main 모듈 임포트 및 실행
from src.main import app
import uvicorn

if __name__ == "__main__":
    print("Starting User Service on port 8101...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8101,
        reload=False,
        log_level="info"
    )