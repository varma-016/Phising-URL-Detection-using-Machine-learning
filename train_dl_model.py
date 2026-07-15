#!/usr/bin/env python3
"""
Train Deep Learning (CNN/LSTM) Model for Phishing Detection
Trains on synthetic phishing dataset and saves model to models/ folder
"""

import os
import logging
import numpy as np
import pandas as pd
from pathlib import Path
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, LSTM, Dense, Dropout, Embedding, MaxPooling1D
from tensorflow.keras.optimizers import Adam
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pickle

from feature_engineering import URLFeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PhishingDatasetGenerator:
    """Generate synthetic phishing dataset for training"""
    
    # Legitimate URL patterns
    LEGITIMATE_URLS = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.youtube.com',
        'https://www.wikipedia.org',
        'https://www.twitter.com',
        'https://www.instagram.com',
        'https://www.linkedin.com',
        'https://www.github.com',
        'https://www.stackoverflow.com',
        'https://www.gmail.com',
        'https://www.outlook.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://www.netflix.com',
        'https://www.spotify.com',
        'https://www.paypal.com',
        'https://www.ebay.com',
        'https://www.reddit.com',
        'https://www.quora.com',
        'https://www.medium.com',
        'https://www.wordpress.com',
        'https://www.shopify.com',
        'https://www.slack.com',
        'https://www.zoom.us',
        'https://www.dropbox.com',
        'https://www.onedriver.com',
        'https://www.icloud.com',
        'https://www.banking.wellsfargo.com',
        'https://www.business.chase.com',
    ]
    
    # Phishing URL patterns
    PHISHING_PATTERNS = {
        'typosquatting': [
            'g00gle.com', 'faceb00k.com', 'y0utube.com', 'tw1tter.com',
            'ins7agram.com', 'l1nkedin.com', 'github1.com', 'amazo0n.com',
            'paypa1.com', 'netfl1x.com', 'spotif7.com', 'reddi7.com',
            'quora1.com', 'dropbo7.com', 'gmai1.com', 'outlo0k.com',
        ],
        'keywords': [
            'https://verify-account.example.com',
            'https://confirm-identity.example.com',
            'https://update-billing.example.com',
            'https://secure-login.example.com',
            'https://urgent-action.example.com',
            'https://validate-credentials.example.com',
            'https://reset-password.example.com',
            'https://banking-security.example.com',
            'https://paypal-verify.example.com',
            'https://amazon-confirm.example.com',
        ],
        'suspicious_tlds': [
            'https://www.example.tk',
            'https://www.example.ml',
            'https://www.example.ga',
            'https://www.example.cf',
        ],
        'ip_address': [
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
        ],
        'shortened': [
            'https://bit.ly/phishing',
            'https://tinyurl.com/hacked',
            'https://ow.ly/malware',
        ],
        'email_spoofing': [
            'https://admin@fake-bank.com',
            'https://paypal@verify.com',
        ]
    }
    
    @staticmethod
    def generate_dataset(num_samples=500):
        """Generate balanced phishing/legitimate dataset"""
        logger.info(f"Generating synthetic dataset with {num_samples} samples...")
        
        urls = []
        labels = []
        
        # Add legitimate URLs
        num_legit = num_samples // 2
        for i in range(num_legit):
            url = PhishingDatasetGenerator.LEGITIMATE_URLS[i % len(PhishingDatasetGenerator.LEGITIMATE_URLS)]
            urls.append(url)
            labels.append(0)  # 0 = Legitimate
        
        # Add phishing URLs
        num_phishing = num_samples - num_legit
        phishing_urls = []
        for pattern_type, pattern_list in PhishingDatasetGenerator.PHISHING_PATTERNS.items():
            phishing_urls.extend(['https://' + url if not url.startswith('http') else url for url in pattern_list])
        
        for i in range(num_phishing):
            url = phishing_urls[i % len(phishing_urls)]
            urls.append(url)
            labels.append(1)  # 1 = Phishing
        
        logger.info(f"Generated {len(urls)} URLs: {sum(labels)} phishing, {len(urls) - sum(labels)} legitimate")
        
        return pd.DataFrame({'url': urls, 'label': labels})


class DLModelTrainer:
    """Train Deep Learning Model for Phishing Detection"""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.scaler = StandardScaler()
        self.model = None
        self.max_url_length = 100
        
    def build_model(self, input_dim):
        """Build CNN+LSTM model"""
        logger.info(f"Building CNN+LSTM model with input dim: {input_dim}...")
        
        model = Sequential([
            # Embedding layer for URL character encoding
            Embedding(256, 64, input_length=self.max_url_length),
            
            # Convolutional layers for feature extraction
            Conv1D(32, 3, activation='relu', padding='same'),
            MaxPooling1D(2),
            Conv1D(64, 3, activation='relu', padding='same'),
            MaxPooling1D(2),
            
            # LSTM layers for sequential pattern detection
            LSTM(64, return_sequences=True, dropout=0.2),
            LSTM(32, dropout=0.2),
            
            # Dense layers for classification
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')  # Binary classification
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        
        logger.info("Model architecture:")
        model.summary()
        
        return model
    
    def encode_urls(self, urls):
        """Convert URLs to character sequences"""
        logger.info("Encoding URLs to character sequences...")
        encoded = []
        
        for url in urls:
            # Convert URL to ascii values
            seq = [ord(c) for c in url[:self.max_url_length]]
            # Pad to max length
            seq += [0] * (self.max_url_length - len(seq))
            encoded.append(seq[:self.max_url_length])
        
        return np.array(encoded)
    
    def train(self, df, epochs=20, batch_size=32):
        """Train the model"""
        logger.info("Starting training...")
        
        # Extract features using URL Feature Extractor
        X_features = np.array([
            self.feature_extractor.extract_features(url)
            for url in df['url']
        ])
        
        # Encode URLs for CNN
        X_encoded = self.encode_urls(df['url'].values)
        
        # Labels
        y = df['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_encoded, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set size: {len(X_train)}")
        logger.info(f"Test set size: {len(X_test)}")
        logger.info(f"Phishing in train: {y_train.sum()}/{len(y_train)}")
        logger.info(f"Phishing in test: {y_test.sum()}/{len(y_test)}")
        
        # Build and train model
        self.model = self.build_model(input_dim=X_features.shape[1])
        
        # Train with early stopping
        early_stop = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=3,
            restore_best_weights=True
        )
        
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            callbacks=[early_stop],
            verbose=1
        )
        
        # Evaluate on test set
        logger.info("Evaluating on test set...")
        test_loss, test_accuracy, test_precision, test_recall = self.model.evaluate(
            X_test, y_test, verbose=0
        )
        
        logger.info(f"Test Accuracy: {test_accuracy:.4f}")
        logger.info(f"Test Precision: {test_precision:.4f}")
        logger.info(f"Test Recall: {test_recall:.4f}")
        logger.info(f"Test F1-Score: {2 * (test_precision * test_recall) / (test_precision + test_recall):.4f}")
        
        return self.model, history, (test_accuracy, test_precision, test_recall)
    
    def save_model(self, filepath='models/cnn_lstm_model.h5'):
        """Save trained model"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self.model.save(filepath)
        logger.info(f"Model saved to {filepath}")


def main():
    """Main training pipeline"""
    print("\n" + "=" * 80)
    print("DEEP LEARNING MODEL TRAINING FOR PHISHING DETECTION".center(80))
    print("=" * 80 + "\n")
    
    try:
        # Generate dataset
        dataset_generator = PhishingDatasetGenerator()
        df = dataset_generator.generate_dataset(num_samples=500)
        
        # Train model
        trainer = DLModelTrainer()
        model, history, metrics = trainer.train(df, epochs=20, batch_size=32)
        
        # Save model
        trainer.save_model('models/cnn_lstm_model.h5')
        
        # Print results
        print("\n" + "=" * 80)
        print("TRAINING COMPLETE!")
        print("=" * 80)
        print(f"Model saved to: models/cnn_lstm_model.h5")
        print(f"Test Accuracy: {metrics[0]:.2%}")
        print(f"Test Precision: {metrics[1]:.2%}")
        print(f"Test Recall: {metrics[2]:.2%}")
        print("=" * 80 + "\n")
        
        print("Next steps:")
        print("1. Start the API: python start_api.py")
        print("2. Test with DL model: curl -X POST http://localhost:8000/predict -d '{\"url\": \"https://g00gle.com\", \"model\": \"dl\"}'")
        print("\n")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
