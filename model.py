import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

# CSV laden
df = pd.read_csv("data.csv")

# Features & Labels
X = df.drop(columns=["category", "website", "filename", "analysis_time"])
y = df["category"]

# Labels encoden
le = LabelEncoder()
y_enc = le.fit_transform(y)

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.3, random_state=42)

# Random Forest
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

# Feature Importance
importances = clf.feature_importances_
feat_names = X.columns

plt.figure(figsize=(10,6))
plt.barh(feat_names, importances)
plt.xlabel("Feature Importance")
plt.ylabel("Feature")
plt.title("Wichtigkeit der DNS-Features für Klassifikation")
plt.show()
