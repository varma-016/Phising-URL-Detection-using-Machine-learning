"""
Setup and Installation Guide
Quick start instructions for the Phishing URL Detection System
"""

# INSTALLATION STEPS

## 1. Prerequisites
- Python 3.8 or higher
- pip package manager
- 2GB+ RAM for model training
- Internet connection (for downloading dependencies)

## 2. Virtual Environment Setup

### On Windows:
```
python -m venv venv
venv\Scripts\activate
```

### On macOS/Linux:
```
python3 -m venv venv
source venv/bin/activate
```

## 3. Install Dependencies
```
pip install -r requirements.txt
```

## 4. Directory Structure
The system will auto-create:
```
data/
├── phishing_urls.csv           (Sample dataset)
└── phishing_detection.db       (SQLite database)

models/
├── random_forest_model.pkl     (ML model)
├── xgboost_model.pkl           (ML model)
├── cnn_model.h5                (DL model)
├── lstm_model.h5               (DL model)
├── scaler.pkl                  (Feature scaler)
├── char_vocab.pkl              (Character vocabulary)
└── *.png                       (Visualizations)
```

## 5. Quick Start

### Option A: Complete Pipeline
```
python main.py --complete
```
This will:
1. Generate sample dataset
2. Train all ML models
3. Train all DL models
4. Generate SHAP explanations
5. Start API server

### Option B: Step-by-Step
```
# Step 1: Generate sample data
python main.py --generate-data

# Step 2: Train ML models
python main.py --train-ml

# Step 3: Train DL models
python main.py --train-dl

# Step 4: Generate explanations
python main.py --explain

# Step 5: Start API
python main.py --run-api
```

### Option C: Start API with Pre-Trained Models
```
python api.py
```

## 6. Using Your Own Dataset

Replace `data/phishing_urls.csv` with your dataset.
Required format:
```
url,label
https://example.com,0
https://malicious.com,1
```

Where:
- `url`: The URL string
- `label`: 0 for legitimate, 1 for phishing

## 7. API Usage

### Start Server:
```
python api.py
```

### Single Prediction:
```
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "model": "ml"}'
```

### Response:
```json
{
  "url": "https://example.com",
  "prediction": 0,
  "prediction_label": "Legitimate",
  "confidence": 0.95,
  "model_used": "Machine Learning (Random Forest/XGBoost)",
  "timestamp": "2026-02-20T10:30:00",
  "features": {...}
}
```

### Batch Prediction:
```
curl -X POST "http://localhost:8000/batch_predict" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://site1.com", "https://site2.com"],
    "model": "ml"
  }'
```

### Get Statistics:
```
curl "http://localhost:8000/stats"
```

Response:
```json
{
  "total_predictions": 150,
  "phishing_detected": 45,
  "legitimate_detected": 105,
  "recent_scans_24h": 23,
  "detection_rate": 30.0
}
```

### View Documentation:
Navigate to:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 8. Testing

Run unit tests:
```
python test_system.py
```

## 9. Troubleshooting

### Issue: ModuleNotFoundError
**Solution**: Ensure virtual environment is activated
```
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux
```

### Issue: Port 8000 already in use
**Solution**: Use different port
```
uvicorn api:app --port 8001
```

### Issue: HTTPS certificate error
**Solution**: The system disables SSL verification for development
- For production, use proper SSL certificates

### Issue: Slow feature extraction
**Solution**: Some URLs take time to extract WHOIS/DNS data
- Network timeout is set to 5 seconds
- Adjust in feature_engineering.py if needed

### Issue: OutOfMemory during training
**Solution**: Reduce dataset size or batch size
- Modify in train_ml.py and train_dl.py

### Issue: TensorFlow GPU not detected
**Solution**: CPU-only installation is default
- Install tensorflow-gpu for GPU support
```
pip install tensorflow-gpu
```

## 10. Performance Tips

1. **Caching**: Database caches predictions to avoid re-processing
2. **Batch Processing**: Use /batch_predict for multiple URLs
3. **Model Selection**: Use 'ml' model for fast inference, 'dl' for higher accuracy
4. **Database Indexes**: Already optimized with indexes

## 11. Production Deployment

### Docker:
```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t phishing-detector .
docker run -p 8000:8000 phishing-detector
```

### Environment Variables:
```
DATABASE_URL=sqlite:///data/phishing_detection.db
API_PORT=8000
LOG_LEVEL=INFO
```

## 12. Configuration

### Adjust Feature Extraction Timeout:
Edit feature_engineering.py:
```python
self.timeout = 10  # Increase from default 5 seconds
```

### Adjust Model Parameters:
Edit train_ml.py and train_dl.py to modify:
- Training epochs
- Batch sizes
- Hyperparameters
- Cross-validation folds

## 13. Monitoring

### View Recent Scans:
```
curl "http://localhost:8000/history"
```

### View Model Information:
```
curl "http://localhost:8000/models"
```

### Check API Health:
```
curl "http://localhost:8000/health"
```

## 14. Data Privacy

The system:
- Stores predictions in local SQLite database
- Does NOT send data to external servers (except during feature extraction for WHOIS/DNS)
- Includes comprehensive logging
- Supports batch processing without storing raw URLs

## 15. Advanced Usage

### Custom Feature Engineering:
Extend URLFeatureExtractor class in feature_engineering.py

### Custom Models:
Implement new model in train_ml.py or train_dl.py

### API Extensions:
Add new endpoints in api.py using FastAPI patterns

### Database Queries:
Use PhishingDetectionDatabase class methods or SQL directly

## 16. Support & Documentation

- README.md: Complete project documentation
- Code comments: Detailed inline documentation
- Docstrings: Function and class documentation
- Test cases: Usage examples in test_system.py

## 17. Next Steps

1. Generate sample data: `python main.py --generate-data`
2. Train models: `python main.py --train-all`
3. Start API: `python main.py --run-api`
4. Test endpoint: Visit http://localhost:8000/docs
5. Make predictions: Use curl or any HTTP client

---

**Total Installation Time**: 5-10 minutes
**Total Training Time**: 30-60 minutes (depending on dataset size)
**Typical API Response Time**: 200-500ms per URL

For questions or issues, refer to README.md and inline code documentation.
