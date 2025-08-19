import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.neighbors import NearestNeighbors
from statsmodels.stats.proportion import proportion_confint


import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from datetime import datetime

class DNSTrafficClassifier:
    def __init__(self):
        self.rf_model = None
        self.category_encoder = LabelEncoder()
        self.website_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names = None
        self.website_similarity = None
        self.training_data = None
        
    def load_and_preprocess_data(self, csv_file):
        """Load and preprocess DNS traffic data"""
        print("Loading DNS traffic data...")
        df = pd.read_csv(csv_file)
        
        # Store original data for similarity analysis
        self.training_data = df.copy()
        
        # Feature engineering
        print("Engineering features...")
        df = self._feature_engineering(df)
        
        # Prepare features and targets
        feature_cols = [col for col in df.columns if col not in 
                       ['category', 'website', 'filename', 'analysis_time']]
        
        X = df[feature_cols]
        y_category = df['category']
        y_website = df['website']
        
        self.feature_names = X.columns.tolist()
        
        # Encode labels
        y_cat_enc = self.category_encoder.fit_transform(y_category)
        y_web_enc = self.website_encoder.fit_transform(y_website)
        
        print(f"Dataset shape: {X.shape}")
        print(f"Categories: {list(self.category_encoder.classes_)}")
        print(f"Websites: {list(self.website_encoder.classes_)}")
        print(f"Features: {self.feature_names}")
        
        return X, y_cat_enc, y_web_enc, df
    
    def _feature_engineering(self, df):
        """Create additional features from DNS metadata"""
        df = df.copy()
        
        # Request/Response ratios
        df['request_response_ratio'] = df['request_count'] / (df['response_count'] + 1)
        df['avg_size_ratio'] = df['request_avg_size'] / (df['response_avg_size'] + 1)
        
        # Traffic intensity features
        df['queries_per_second'] = df['total_dns_queries'] / (df['duration_seconds'] + 0.1)
        df['requests_per_second'] = df['request_count'] / (df['duration_seconds'] + 0.1)
        
        # Size variation features
        df['request_size_range'] = df['request_max_size'] - df['request_min_size']
        df['response_size_range'] = df['response_max_size'] - df['response_min_size']
        df['request_size_variance'] = df['request_size_range'] / (df['request_avg_size'] + 1)
        df['response_size_variance'] = df['response_size_range'] / (df['response_avg_size'] + 1)
        
        # Traffic pattern features
        df['total_traffic_volume'] = (df['request_count'] * df['request_avg_size'] + 
                                     df['response_count'] * df['response_avg_size'])
        df['efficiency_ratio'] = df['response_count'] / (df['request_count'] + 1)
        
        return df
    
    def train_model(self, X, y_category, optimize_hyperparams=True):
        """Train the Random Forest classifier with optional hyperparameter optimization"""
        print("Training Random Forest classifier...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_category, test_size=0.3, random_state=42, stratify=y_category
        )
        
        if optimize_hyperparams:
            print("Optimizing hyperparameters...")
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 15, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2']
            }
            
            rf = RandomForestClassifier(random_state=42)
            grid_search = GridSearchCV(rf, param_grid, cv=5, scoring='accuracy', n_jobs=-1)
            grid_search.fit(X_train, y_train)
            
            self.rf_model = grid_search.best_estimator_
            print(f"Best parameters: {grid_search.best_params_}")
            print(f"Best CV score: {grid_search.best_score_:.4f}")
        else:
            # Use default parameters optimized for traffic analysis
            self.rf_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                random_state=42
            )
            self.rf_model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.rf_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # 95%-Konfidenzintervall (Wilson)
        n = len(y_test)
        correct = (y_test == y_pred).sum()
        ci_low, ci_high = proportion_confint(count=correct, nobs=n, alpha=0.05, method="wilson")
        
        print(f"\nModel Performance:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"95% CI for Accuracy: [{ci_low:.4f}, {ci_high:.4f}]")
        print(f"Cross-validation scores: {cross_val_score(self.rf_model, X_scaled, y_category, cv=5).mean():.4f}")
        
        # Detailed classification report
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                target_names=self.category_encoder.classes_))
        
        return X_test, y_test, y_pred

    
    def setup_similarity_search(self, X):
        """Setup similarity search for finding similar websites"""
        print("Setting up website similarity search...")
        X_scaled = self.scaler.transform(X)
        self.website_similarity = NearestNeighbors(n_neighbors=5, metric='cosine')
        self.website_similarity.fit(X_scaled)
    
    def predict_category_and_similarity(self, features_dict):
        """Predict category and find similar websites for new DNS traffic"""
        # Convert input to DataFrame
        input_df = pd.DataFrame([features_dict])
        
        # Apply same feature engineering
        input_df = self._feature_engineering(input_df)
        
        # Extract features in correct order
        X_input = input_df[self.feature_names].values
        X_input_scaled = self.scaler.transform(X_input)
        
        # Predict category
        category_pred = self.rf_model.predict(X_input_scaled)[0]
        category_proba = self.rf_model.predict_proba(X_input_scaled)[0]
        category_name = self.category_encoder.inverse_transform([category_pred])[0]
        
        # Find similar websites
        distances, indices = self.website_similarity.kneighbors(X_input_scaled)
        similar_websites = []
        
        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            website = self.training_data.iloc[idx]['website']
            category = self.training_data.iloc[idx]['category']
            similarity = 1 - dist  # Convert distance to similarity
            similar_websites.append({
                'website': website,
                'category': category,
                'similarity': similarity
            })
        
        # Get prediction confidence
        max_proba = np.max(category_proba)
        confidence_categories = []
        for i, prob in enumerate(category_proba):
            if prob > 0.1:  # Only show categories with >10% probability
                cat_name = self.category_encoder.inverse_transform([i])[0]
                confidence_categories.append({'category': cat_name, 'probability': prob})
        
        confidence_categories.sort(key=lambda x: x['probability'], reverse=True)
        
        return {
            'predicted_category': category_name,
            'confidence': max_proba,
            'category_probabilities': confidence_categories,
            'similar_websites': similar_websites
        }
    
    def plot_feature_importance(self):
        """Plot feature importance"""
        if self.rf_model is None:
            print("Model not trained yet!")
            return
        
        importances = self.rf_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title("DNS Traffic Feature Importance for Website Classification")
        plt.barh(range(len(importances)), importances[indices])
        plt.yticks(range(len(importances)), [self.feature_names[i] for i in indices])
        plt.xlabel("Feature Importance")
        plt.tight_layout()
        plt.savefig('dns_feature_importance_optimized.png', dpi=300, bbox_inches='tight')
        print("Feature importance plot saved as 'dns_feature_importance_optimized.png'")
        
        # Print top features
        print("\nTop 10 Most Important Features:")
        for i in range(min(10, len(importances))):
            idx = indices[i]
            print(f"{i+1:2d}. {self.feature_names[idx]:25s} ({importances[idx]:.4f})")
    
    def save_model(self, filename_prefix="dns_classifier"):
        """Save the trained model"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.joblib"
        
        model_data = {
            'rf_model': self.rf_model,
            'category_encoder': self.category_encoder,
            'website_encoder': self.website_encoder,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'website_similarity': self.website_similarity,
            'training_data': self.training_data
        }
        
        joblib.dump(model_data, filename)
        print(f"Model saved as '{filename}'")
        return filename
    
    def load_model(self, filename):
        """Load a saved model"""
        model_data = joblib.load(filename)
        self.rf_model = model_data['rf_model']
        self.category_encoder = model_data['category_encoder']
        self.website_encoder = model_data['website_encoder']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.website_similarity = model_data['website_similarity']
        self.training_data = model_data['training_data']
        print(f"Model loaded from '{filename}'")

def main():
    # Initialize classifier
    classifier = DNSTrafficClassifier()
    
    # Load and preprocess data
    X, y_category, y_website, df = classifier.load_and_preprocess_data("data.csv")
    
    # Train model
    X_test, y_test, y_pred = classifier.train_model(X, y_category, optimize_hyperparams=False)
    
    # Setup similarity search
    classifier.setup_similarity_search(X)
    
    # Plot feature importance
    classifier.plot_feature_importance()
    
    # Save model
    model_file = classifier.save_model()
    
    # Example prediction
    print("\n" + "="*60)
    print("EXAMPLE PREDICTION")
    print("="*60)
    
    # Example new DNS traffic entry
    new_traffic = {
        'total_dns_queries': 85,
        'unique_clients': 1,
        'request_count': 87,
        'request_avg_size': 315.5,
        'request_min_size': 24,
        'request_max_size': 1200,
        'response_count': 180,
        'response_avg_size': 125.3,
        'response_min_size': 2,
        'response_max_size': 2880,
        'duration_seconds': 35.2
    }
    
    # Make prediction
    result = classifier.predict_category_and_similarity(new_traffic)
    
    print(f"Predicted Category: {result['predicted_category']}")
    print(f"Confidence: {result['confidence']:.2%}")
    
    print(f"\nCategory Probabilities:")
    for cat in result['category_probabilities']:
        print(f"  {cat['category']:15s}: {cat['probability']:.2%}")
    
    print(f"\nSimilar Websites:")
    for i, site in enumerate(result['similar_websites'], 1):
        print(f"  {i}. {site['website']:15s} ({site['category']:10s}) - Similarity: {site['similarity']:.2%}")
    
    return classifier

if __name__ == "__main__":
    classifier = main()