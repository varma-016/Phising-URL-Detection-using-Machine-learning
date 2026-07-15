"""
Simple API Starter - Automatically picks the right API version
"""

import sys
import logging
import time
import webbrowser
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def start_api():
    """Start the appropriate API version"""
    
    logger.info("="*70)
    logger.info("PHISHING URL DETECTION - API SERVER")
    logger.info("="*70)
    
    # Try to start the full API with trained models first
    models_path = Path(__file__).parent / "models"
    has_models = models_path.exists() and any(models_path.iterdir())
    
    if has_models:
        logger.info("\n📍 Attempting to start Full API (with trained models)...")
        try:
            import api
            import uvicorn
            
            logger.info("✅ Full API loaded successfully!")
            logger.info("\n" + "="*70)
            logger.info("API Server Starting on http://localhost:8000")
            logger.info("="*70)
            logger.info("Scanner Interface: Opening in browser...")
            logger.info("API Documentation: http://localhost:8000/docs")
            logger.info("Press Ctrl+C to stop the server\n")
            
            # Try to open scanner.html
            time.sleep(1)
            try:
                login_path = Path(__file__).parent / "login.html"
                if login_path.exists():
                    webbrowser.open(f"file:///{login_path.absolute()}")
                    logger.info(f"✅ Opening Login page: {login_path}\n")
            except Exception as e:
                logger.warning(f"Could not open browser: {e}\n")
            
            # Run the full API
            import uvicorn
            uvicorn.run(api.app, host="0.0.0.0", port=8000, log_level="info")
            return
        except Exception as e:
            logger.warning(f"Failed to load full API: {e}\n")
    
    # Fallback to simplified API
    logger.info("\n📍 Starting Simplified API (mock version - works immediately)...")
    try:
        import api_simple
        import uvicorn
        
        logger.info("✅ Simplified API loaded successfully!")
        logger.info("\n" + "="*70)
        logger.info("API Server Starting on http://localhost:8000")
        logger.info("="*70)
        logger.info("Scanner Interface: Opening in browser...")
        logger.info("API Documentation: http://localhost:8000/docs")
        logger.info("Press Ctrl+C to stop the server")
        logger.info("\n⚠️  Using simplified API (no trained models)")
        logger.info("To use trained models, run: python train_ml.py && python train_dl.py\n")
        
        # Try to open login page
        time.sleep(1)
        try:
            login_path = Path(__file__).parent / "login.html"
            if login_path.exists():
                webbrowser.open(f"file:///{login_path.absolute()}")
                logger.info(f"✅ Opening Login page: {login_path}\n")
        except Exception as e:
            logger.warning(f"Could not open browser: {e}\n")
        
        # Run the simplified API
        import uvicorn
        uvicorn.run(api_simple.app, host="0.0.0.0", port=8000, log_level="info")
        
    except Exception as e:
        logger.warning(f"\n⚠️  Full API failed to load: {str(e)}")
        logger.info("\n" + "="*70)
        logger.info("FALLBACK: Starting Simple Mock API (no models needed)")
        logger.info("="*70)
        
        try:
            import api_simple
            import uvicorn
            
            logger.info("\n✅ Mock API loaded successfully!")
            logger.info("\n" + "="*70)
            logger.info("API Server Starting on http://localhost:8000")
            logger.info("(Using mock predictions - models not loaded)")
            logger.info("="*70)
            logger.info("Scanner Interface: Opening in browser...")
            logger.info("API Documentation: http://localhost:8000/docs")
            logger.info("Press Ctrl+C to stop the server\n")
            
            # Try to open login.html
            time.sleep(1)
            try:
                login_path = Path(__file__).parent / "login.html"
                if login_path.exists():
                    webbrowser.open(f"file:///{login_path.absolute()}")
                    logger.info(f"✅ Opening Login page: {login_path}\n")
            except Exception as e:
                logger.warning(f"Could not open browser: {e}\n")
            
            # Run the mock API
            uvicorn.run(api_simple.app, host="0.0.0.0", port=8000, log_level="info")
            
        except Exception as e2:
            logger.error(f"\n❌ FATAL ERROR: Both APIs failed!")
            logger.error(f"Full API Error: {str(e)}")
            logger.error(f"Mock API Error: {str(e2)}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        start_api()
    except KeyboardInterrupt:
        logger.info("\n\nServer stopped by user (Ctrl+C)")
        sys.exit(0)
