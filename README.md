# Phishing URL Detection System

A complete end-to-end machine learning and deep learning system for detecting phishing URLs with production-ready API backend.

## Features

### 1. **Advanced Feature Engineering**
- **30+ URL Features**: Length, dots, special characters, @ symbol, IP address detection, HTTPS usage, subdomains, suspicious keywords, etc.
- **Domain Features**: Domain age, expiry duration, DNS records, SSL certificate validation, port analysis
- **Content Features**: iFrame detection, hidden forms, external favicon, form action mismatch, JavaScript obfuscation, meta redirects
- **Intelligent Feature Extraction**: Uses WHOIS, DNS, and web scraping to extract comprehensive features

### 2. **Machine Learning Models**
- **Random Forest Classifier**: With hyperparameter tuning using GridSearchCV
- **XGBoost Classifier**: Gradient boosting with cross-validation
- **SMOTE**: Handles class imbalance in training data
- **Feature Scaling**: StandardScaler for normalized feature values
- **Comprehensive Evaluation**: Accuracy, Precision, Recall, F1-Score, Confusion Matrix

### 3. **Deep Learning Models**
- **Character-Level CNN**: Convolutional Neural Network for URL classification
- **Bidirectional LSTM**: Long Short-Term Memory networks for sequence modeling
- **Embedding Layer**: Character-to-index encoding with padding
- **Training History Visualization**: Loss and accuracy plots

### 4. **Model Explainability**
- **SHAP Integration**: SHapley Additive exPlanations for model transparency
- **Global Explanations**: Feature importance across all predictions
- **Local Explanations**: Individual prediction explanations
- **Dependence Plots**: Feature relationship analysis
- **Force Plots**: Visual explanation of predictions

### 5. **FastAPI Backend**
- **REST API Endpoints**:
  - `/predict`: Single URL prediction
  - `/batch_predict`: Multiple URLs in batch
  - `/health`: API health check
  - `/stats`: Detection statistics
  - `/history`: Scan history
  - `/models`: Model information
- **CORS Support**: Cross-Origin Resource Sharing enabled
- **Error Handling**: Comprehensive error handling and logging
- **Background Tasks**: Asynchronous database operations

### 6. **SQLite Database**
- **Predictions Table**: Store classification results
- **Scan History**: Track all scans with timestamps
- **Models Table**: Store model performance metrics
- **Indexes**: Optimized queries for fast retrieval
- **Statistics**: Detection rates and trends

### 7. **Production-Ready Structure**
- Modular design with separate modules
- Comprehensive logging
- Error handling throughout
- Documentation and comments
- Requirements.txt for dependency management

## Project Structure

```
phishing-detection/
├── data/                           # Dataset directory
│   └── phishing_urls.csv          # Input dataset
├── models/                         # Trained models directory
│   ├── random_forest_model.pkl    # ML model
│   ├── xgboost_model.pkl          # XGBoost model
│   ├── cnn_model.h5               # Deep learning CNN model
│   ├── lstm_model.h5              # Deep learning LSTM model
│   ├── scaler.pkl                 # Feature scaler
│   ├── char_vocab.pkl             # Character vocabulary
│   └── *.png                      # Visualizations
├── feature_engineering.py          # Feature extraction (30+ features)
├── train_ml.py                     # ML model training pipeline
├── train_dl.py                     # DL model training pipeline
├── shap_explain.py                 # Model explainability
├── database.py                     # SQLite database management
├── api.py                          # FastAPI backend
├── requirements.txt                # Python dependencies
└── README.md                       # Documentation
```

## Installation

## Quick Deployment (Docker)

This project now includes a production Docker setup for the lightweight API (`api_simple.py`).

### 1. Build image
```bash
docker build -t phishing-detector:latest .
```

### 2. Run container
```bash
docker run -d -p 8000:8000 --name phishing-detector phishing-detector:latest
```

### 3. Open app
- Login page: `http://localhost:8000/static/login.html`
- API docs: `http://localhost:8000/docs`

### 4. Deploy to cloud (Render/Railway/Azure Web App)
- Push this repository to GitHub
- Create a new service from the repo
- Use Docker deployment (it will detect `Dockerfile`)
- Set `PORT=8000` if your platform requires it


### 1. Clone/Setup Project
```bash
cd phishing-detection
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Prepare Dataset
- Place your CSV file at `data/phishing_urls.csv`
- Expected columns: `url`, `label` (0=legitimate, 1=phishing)
- Dataset should have at least 1000+ URLs for good model performance

## Usage

### 1. Train Machine Learning Models
```bash
python train_ml.py
```
- Trains Random Forest and XGBoost models
- Performs hyperparameter tuning with cross-validation
- Saves models to `models/` directory
- Generates feature importance and confusion matrix plots

### 2. Train Deep Learning Models
```bash
python train_dl.py
```
- Trains CNN and LSTM models
- Uses character-level encoding
- Evaluates performance metrics
- Saves models and training history plots

### 3. Generate Model Explanations
```bash
python shap_explain.py
```
- Creates SHAP explanations for models
- Generates global feature importance
- Provides local prediction explanations
- Creates visualization plots

### 4. Start API Server
```bash
python api.py
```
Or manually:
```bash
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

### 5. API Usage Examples

#### Single URL Prediction
```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "model": "ml"}'
```

#### Batch Prediction
```bash
curl -X POST "http://localhost:8000/batch_predict" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://site1.com", "https://site2.com"], "model": "ml"}'
```

#### Get Statistics
```bash
curl "http://localhost:8000/stats"
```

#### API Documentation
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Feature List (30+)

### URL-Based Features (12)
1. URL length
2. Number of dots
3. Special characters count
4. @ symbol presence
5. IP address detection
6. HTTPS usage
7. Subdomain count
8. Suspicious keywords count
9. Digits count
10. Hyphen count
11. Redirection count (//)
12. Query parameter count

### Domain-Based Features (8)
13. Domain length
14. Domain age (days)
15. Expiry duration (days)
16. DNS record existence
17. SSL certificate validity
18. Port number
19. Non-standard port flag
20. URL path length

### Content-Based Features (10+)
21. iFrame detection
22. Hidden forms count
23. External favicon detection
24. Form action mismatch count
25. Script tags count
26. Obfuscated JavaScript count
27. External links count
28. Meta refresh detection
29. Page title length
30. Input fields count

## Model Performance

The system trains multiple models and compares their performance:

- **Random Forest**: Fast, interpretable, good baseline
- **XGBoost**: Higher accuracy with boosting
- **CNN**: Character-level deep learning
- **LSTM**: Sequential pattern learning

All models include:
- Accuracy metrics
- Precision and Recall
- F1-Score
- Confusion matrix
- Cross-validation

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API information |
| GET | `/health` | Health check |
| POST | `/predict` | Single URL prediction |
| POST | `/batch_predict` | Batch URL prediction |
| GET | `/stats` | Detection statistics |
| GET | `/history` | Scan history |
| GET | `/models` | Model information |

## Database Schema

### predictions
- id: Primary key
- url: Unique URL
- prediction: Binary (0/1)
- confidence: Prediction confidence
- model_name: Model used
- timestamp: Prediction time
- features_json: Extracted features

### scan_history
- id: Primary key
- url: Scanned URL
- is_phishing: Classification result
- model_used: Model name
- confidence: Confidence score
- processing_time_ms: Processing duration

### models
- id: Primary key
- model_name: Unique model name
- model_type: Type of model
- accuracy, precision, recall, f1_score: Metrics

## Docker Deployment

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:
```bash
docker build -t phishing-detector .
docker run -p 8000:8000 phishing-detector
```

## Requirements

Key dependencies:
- pandas, numpy: Data processing
- scikit-learn: Machine learning
- xgboost: Gradient boosting
- tensorflow/keras: Deep learning
- fastapi, uvicorn: API server
- requests, beautifulsoup4: Web scraping
- shap: Model explainability
- whois, dnspython: Domain analysis
- SQLAlchemy: Database ORM

See `requirements.txt` for complete list.

## Performance Optimization

1. **Feature Extraction**: Caching of WHOIS queries
2. **Model Inference**: Fast batch predictions
3. **Database**: Indexed queries for quick lookups
4. **API**: Asynchronous background tasks
5. **Scaling**: Stateless API design for horizontal scaling

## Best Practices

1. **Regular Model Retraining**: Update models with new phishing patterns
2. **Monitoring**: Track API performance and detection rates
3. **Version Control**: Maintain model versions
4. **Security**: Use HTTPS for production
5. **Rate Limiting**: Add rate limiting for production deployment
6. **Authentication**: Implement API key authentication

## Troubleshooting

### Models not found
- Ensure you've trained models: `python train_ml.py` and `python train_dl.py`
- Check `models/` directory exists

### Database errors
- Ensure write permissions in project directory
- Database is auto-created in `data/phishing_detection.db`

### Feature extraction timeout
- Increase timeout in `feature_engineering.py`
- Some domains may be slow to respond

### SHAP explanation errors
- Requires sufficient data samples
- May take time for large datasets

## Future Enhancements

- [ ] Real-time model updates
- [ ] Ensemble methods combining all models
- [ ] Advanced DNS/WHOIS caching
- [ ] Browser extension integration
- [ ] Mobile app
- [ ] Advanced analytics dashboard
- [ ] A/B testing framework
- [ ] Automated model retraining pipeline

## Academic Use

This project is suitable for:
- Machine Learning course projects
- Deep Learning capstone
- Cybersecurity research
- Academic paper implementation
- University project submission

## References

- SHAP Documentation: https://shap.readthedocs.io/
- FastAPI: https://fastapi.tiangolo.com/
- Scikit-learn: https://scikit-learn.org/
- TensorFlow: https://www.tensorflow.org/
- XGBoost: https://xgboost.readthedocs.io/

## License

This project is provided as-is for educational and research purposes.

## Author

Created as a complete production-ready phishing URL detection system demonstrating:
- Machine Learning best practices
- Deep Learning implementation
- API design and development
- Database management
- Model explainability
- Production deployment

---

**Last Updated**: February 2026
**Version**: 1.0.0
