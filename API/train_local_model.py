import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report
import joblib

# Load dataset
df = pd.read_csv(r"C:\Users\LENOVO\Desktop\Personal Project\Final Year Project\data\final_balanced_dataset_v2.csv")

# Combine text features
df['combined_text'] = (
    df['vulnerable_code'].fillna('') + ' ' + 
    df['attack_payload'].fillna('') + ' ' + 
    df['language'].fillna('') + ' ' + 
    df['technique'].fillna('') + ' ' + 
    df['real_incident'].fillna('') + ' ' + 
    df['conversation_text'].fillna('')
)

# Target
y = df['severity']

# Convert text to numbers
vectorizer = TfidfVectorizer(max_features=1000)
X = vectorizer.fit_transform(df['combined_text'])

# Train model
model = GradientBoostingClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=3,
    random_state=42
)

# Cross-validation
scores = cross_val_score(model, X, y, cv=5)
print(f"Cross-validation accuracy: {scores.mean():.2%} (+/- {scores.std()*2:.2%})")

# Train on full data
model.fit(X, y)

# Test on holdout
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
print(f"Holdout accuracy: {(y_pred == y_test).mean():.2%}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save
joblib.dump(model, "API/severity_model_local.pkl")
joblib.dump(vectorizer, "API/vectorizer_local.pkl")

print("\nLocal model saved: API/severity_model_local.pkl")
print("Vectorizer saved: API/vectorizer_local.pkl")