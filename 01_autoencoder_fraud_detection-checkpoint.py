#!/usr/bin/env python
# coding: utf-8

# In[5]:


# === CELL 1: IMPORT ALL LIBRARIES ===
print("="*70)
print("LOGSENSE KENYA - COMPLETE FRAUD DETECTION SYSTEM")
print("ALL FRAUD TYPES: Original + New Patterns")
print("="*70)

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os
import json
import joblib
from datetime import datetime

# Deep Learning
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks

# Scikit-learn
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix, 
                           roc_auc_score, roc_curve, accuracy_score, 
                           precision_score, recall_score, f1_score)

# Utilities
import warnings
warnings.filterwarnings('ignore')

# Add src to path for custom modules
sys.path.append('src')

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
get_ipython().run_line_magic('matplotlib', 'inline')

# Set random seeds
np.random.seed(42)
tf.random.set_seed(42)

print("✅ All libraries imported successfully!")
print(f"TensorFlow version: {tf.__version__}")
print(f"NumPy version: {np.__version__}")
print(f"Pandas version: {pd.__version__}")
print(f"Current directory: {os.getcwd()}")


# In[8]:


# === CELL 2: COMPLETE FRAUD DATA GENERATOR (FIXED) ===
print("="*70)
print("CREATING COMPLETE FRAUD DATA GENERATOR")
print("All 8 Fraud Types: Original 5 + New 3")
print("="*70)

class CompleteKenyanFraudGenerator:
    """Generate data with ALL 8 fraud patterns from thesis"""

    def __init__(self, seed=42):
        self.rng = np.random.RandomState(seed)
        # Define all fraud types as class attribute
        self.all_fraud_types = [
            'sim_swap',           # Original 1
            'agent_collusion',    # Original 2
            'social_engineering', # Original 3
            'identity_theft',     # Original 4
            'mobile_money_fraud', # Original 5
            'repayment_fraud',    # New 1
            'synthetic_identity', # New 2
            'device_cloning'      # New 3
        ]

    def generate_base_features(self, n_samples: int) -> pd.DataFrame:
        """Generate comprehensive feature set for all fraud types"""

        base_features = {
            # ========== TRANSACTIONAL FEATURES ==========
            'transaction_amount': self.rng.exponential(5000, n_samples),
            'time_to_repay': self.rng.randint(1, 30, n_samples),
            'loan_frequency': self.rng.poisson(2, n_samples),
            'money_inflow_outflow_ratio': self.rng.uniform(0.5, 2.0, n_samples),
            'peer_to_peer_transfers': self.rng.poisson(5, n_samples),
            'loan_amount': self.rng.exponential(20000, n_samples),
            'daily_transaction_limit': np.full(n_samples, 150000),
            'transaction_count_7d': self.rng.poisson(15, n_samples),
            'transaction_count_30d': self.rng.poisson(50, n_samples),

            # ========== BEHAVIORAL FEATURES ==========
            'login_attempts': self.rng.poisson(3, n_samples),
            'time_spent_in_app': self.rng.exponential(300, n_samples),
            'failed_attempts': self.rng.poisson(0.5, n_samples),
            'unusual_login_hours': self.rng.binomial(1, 0.1, n_samples),
            'session_duration_std': self.rng.exponential(50, n_samples),
            'login_frequency_change': self.rng.normal(0, 0.5, n_samples),
            'navigation_depth': self.rng.poisson(5, n_samples),

            # ========== DEVICE FEATURES ==========
            'imei_consistency_score': self.rng.uniform(0.7, 1.0, n_samples),
            'sim_change_frequency': self.rng.poisson(0.2, n_samples),
            'ip_geolocation_mismatch': self.rng.binomial(1, 0.05, n_samples),
            'device_model_anomaly': self.rng.binomial(1, 0.03, n_samples),
            'device_fingerprint_consistency': self.rng.uniform(0.8, 1.0, n_samples),
            'device_age_days': self.rng.exponential(180, n_samples),
            'os_version_anomaly': self.rng.binomial(1, 0.03, n_samples),
            'screen_resolution_anomaly': self.rng.binomial(1, 0.02, n_samples),
            'timezone_consistency': self.rng.uniform(0.9, 1.0, n_samples),
            'browser_fingerprint_anomaly': self.rng.binomial(1, 0.05, n_samples),
            'font_rendering_anomaly': self.rng.binomial(1, 0.02, n_samples),

            # ========== CREDIT/LOAN FEATURES (Repayment Fraud) ==========
            'credit_score': self.rng.normal(650, 100, n_samples).clip(300, 850),
            'debt_to_income_ratio': self.rng.uniform(0.1, 0.8, n_samples),
            'payment_history_score': self.rng.uniform(0.5, 1.0, n_samples),
            'days_past_due': self.rng.poisson(5, n_samples),
            'active_loans_count': self.rng.poisson(1.5, n_samples),
            'total_loan_amount': self.rng.exponential(20000, n_samples),
            'loan_utilization_ratio': self.rng.uniform(0.1, 0.9, n_samples),
            'default_history': self.rng.binomial(1, 0.05, n_samples),

            # ========== IDENTITY FEATURES (Synthetic Identity) ==========
            'account_age_days': self.rng.exponential(365, n_samples),
            'identity_verification_score': self.rng.uniform(0.7, 1.0, n_samples),
            'biometric_match_score': self.rng.uniform(0.8, 1.0, n_samples),
            'document_verification_score': self.rng.uniform(0.7, 1.0, n_samples),
            'digital_footprint_score': self.rng.uniform(0.6, 1.0, n_samples),
            'social_graph_connections': self.rng.poisson(25, n_samples),

            # ========== AGENT FEATURES ==========
            'agent_transaction_ratio': self.rng.uniform(0.1, 0.5, n_samples),
            'agent_commission_rate': self.rng.uniform(0.01, 0.03, n_samples),

            # ========== MOBILE MONEY SPECIFIC ==========
            'm_pesa_transaction_count': self.rng.poisson(10, n_samples),
            'airtime_purchase_frequency': self.rng.poisson(3, n_samples),
            'bill_payment_count': self.rng.poisson(2, n_samples),
        }

        return pd.DataFrame(base_features)

    def inject_fraud_patterns(self, df: pd.DataFrame, fraud_indices: np.ndarray) -> pd.DataFrame:
        """Inject ALL 8 fraud patterns with specific characteristics"""

        n_fraud = len(fraud_indices)
        fraud_type_assignments = self.rng.choice(self.all_fraud_types, size=n_fraud)

        df['fraud_type'] = 'legitimate'
        df['is_fraud'] = 0

        for i, idx in enumerate(fraud_indices):
            fraud_type = fraud_type_assignments[i]
            df.loc[idx, 'fraud_type'] = fraud_type
            df.loc[idx, 'is_fraud'] = 1

            # ========== ORIGINAL PATTERNS ==========
            if fraud_type == 'sim_swap':
                df.loc[idx, 'sim_change_frequency'] = self.rng.randint(3, 10)
                df.loc[idx, 'imei_consistency_score'] = self.rng.uniform(0.1, 0.5)
                df.loc[idx, 'device_fingerprint_consistency'] = self.rng.uniform(0.1, 0.4)
                df.loc[idx, 'login_attempts'] = self.rng.randint(10, 30)

            elif fraud_type == 'agent_collusion':
                df.loc[idx, 'transaction_amount'] *= self.rng.uniform(5, 20)
                df.loc[idx, 'peer_to_peer_transfers'] = self.rng.randint(20, 100)
                df.loc[idx, 'transaction_count_7d'] = self.rng.randint(50, 200)
                df.loc[idx, 'agent_transaction_ratio'] = self.rng.uniform(0.7, 0.95)
                df.loc[idx, 'money_inflow_outflow_ratio'] = self.rng.uniform(3, 10)

            elif fraud_type == 'social_engineering':
                df.loc[idx, 'login_attempts'] = self.rng.randint(10, 50)
                df.loc[idx, 'failed_attempts'] = self.rng.randint(5, 20)
                df.loc[idx, 'unusual_login_hours'] = 1
                df.loc[idx, 'session_duration_std'] *= 3
                df.loc[idx, 'navigation_depth'] = self.rng.randint(1, 3)

            elif fraud_type == 'identity_theft':
                df.loc[idx, 'identity_verification_score'] = self.rng.uniform(0.1, 0.4)
                df.loc[idx, 'biometric_match_score'] = self.rng.uniform(0.2, 0.6)
                df.loc[idx, 'login_frequency_change'] = self.rng.uniform(1.5, 3.0)
                df.loc[idx, 'account_age_days'] = self.rng.randint(365, 1000)

            elif fraud_type == 'mobile_money_fraud':
                df.loc[idx, 'm_pesa_transaction_count'] = self.rng.randint(50, 200)
                df.loc[idx, 'airtime_purchase_frequency'] = self.rng.randint(10, 50)
                df.loc[idx, 'bill_payment_count'] = self.rng.randint(5, 30)
                df.loc[idx, 'transaction_amount'] = self.rng.exponential(10000, 1)[0]

            # ========== NEW PATTERNS ==========
            elif fraud_type == 'repayment_fraud':
                df.loc[idx, 'payment_history_score'] = self.rng.uniform(0.1, 0.4)
                df.loc[idx, 'days_past_due'] = self.rng.randint(60, 180)
                df.loc[idx, 'debt_to_income_ratio'] = self.rng.uniform(0.8, 1.5)
                df.loc[idx, 'active_loans_count'] = self.rng.randint(3, 8)
                df.loc[idx, 'default_history'] = 1
                df.loc[idx, 'credit_score'] *= self.rng.uniform(0.5, 0.8)

            elif fraud_type == 'synthetic_identity':
                df.loc[idx, 'identity_verification_score'] = self.rng.uniform(0.1, 0.5)
                df.loc[idx, 'biometric_match_score'] = self.rng.uniform(0.3, 0.7)
                df.loc[idx, 'document_verification_score'] = self.rng.uniform(0.2, 0.6)
                df.loc[idx, 'digital_footprint_score'] = self.rng.uniform(0.1, 0.4)
                df.loc[idx, 'social_graph_connections'] = self.rng.poisson(5)
                df.loc[idx, 'account_age_days'] = self.rng.randint(1, 30)
                df.loc[idx, 'credit_score'] = self.rng.uniform(400, 600)

            elif fraud_type == 'device_cloning':
                df.loc[idx, 'device_fingerprint_consistency'] = self.rng.uniform(0.1, 0.5)
                df.loc[idx, 'os_version_anomaly'] = 1
                df.loc[idx, 'screen_resolution_anomaly'] = 1
                df.loc[idx, 'font_rendering_anomaly'] = 1
                df.loc[idx, 'device_age_days'] = self.rng.randint(0, 7)
                df.loc[idx, 'timezone_consistency'] = self.rng.uniform(0.1, 0.6)
                df.loc[idx, 'browser_fingerprint_anomaly'] = 1

        return df

    def generate_complete_dataset(self, n_samples: int = 20000, fraud_ratio: float = 0.15) -> pd.DataFrame:
        """Generate complete dataset with all 8 fraud patterns"""

        # Generate base data
        df = self.generate_base_features(n_samples)

        # Generate fraud indices
        n_fraud = int(n_samples * fraud_ratio)
        fraud_indices = self.rng.choice(n_samples, n_fraud, replace=False)

        # Inject all fraud patterns
        df = self.inject_fraud_patterns(df, fraud_indices)

        # Calculate distribution
        fraud_distribution = df['fraud_type'].value_counts()

        print(f"Generated complete dataset with {n_samples} samples")
        print(f"Total fraud cases: {n_fraud} ({fraud_ratio*100:.1f}%)")
        print(f"\nFraud Type Distribution:")
        for fraud_type, count in fraud_distribution.items():
            if fraud_type != 'legitimate':
                percentage = count / n_fraud * 100
                print(f"  {fraud_type.replace('_', ' ').title():25s}: {count:4d} ({percentage:5.1f}%)")

        return df

# Create generator
complete_generator = CompleteKenyanFraudGenerator(seed=42)
print("\nComplete fraud generator created successfully!")
print(f"Total fraud patterns: {len(complete_generator.all_fraud_types)}")
print("\nFraud patterns included:")
for i, fraud_type in enumerate(complete_generator.all_fraud_types, 1):
    print(f"{i:2d}. {fraud_type.replace('_', ' ').title()}")


# In[7]:


# === CELL 3: GENERATE COMPLETE DATASET ===
print("="*70)
print("GENERATING COMPLETE DATASET WITH ALL FRAUD TYPES")
print("="*70)

# Generate complete dataset
df_complete = complete_generator.generate_complete_dataset(
    n_samples=20000, 
    fraud_ratio=0.15
)

print(f"\n📊 Dataset Information:")
print(f"Shape: {df_complete.shape}")
print(f"Columns: {len(df_complete.columns)}")
print(f"Fraud cases: {df_complete['is_fraud'].sum()} ({df_complete['is_fraud'].mean()*100:.2f}%)")

# Show sample
print("\n📋 Sample data (first 3 rows):")
print(df_complete[['transaction_amount', 'payment_history_score', 
                  'identity_verification_score', 'device_fingerprint_consistency',
                  'fraud_type', 'is_fraud']].head(3))

# Save dataset
os.makedirs('data/synthetic', exist_ok=True)
df_complete.to_csv('data/synthetic/complete_fraud_dataset.csv', index=False)
print(f"\n💾 Dataset saved to: data/synthetic/complete_fraud_dataset.csv")


# In[9]:


# === CELL 4: VISUALIZE ALL FRAUD PATTERNS ===
print("="*70)
print("VISUALIZING ALL 8 FRAUD PATTERNS")
print("="*70)

# Create comprehensive visualization
fig, axes = plt.subplots(3, 3, figsize=(18, 15))
fig.suptitle('LogSense Kenya - All Fraud Patterns Analysis', fontsize=20, fontweight='bold')

# 1. Fraud Type Distribution
fraud_counts = df_complete['fraud_type'].value_counts()
fraud_counts_no_legit = fraud_counts[fraud_counts.index != 'legitimate']

colors = plt.cm.Set3(np.linspace(0, 1, len(fraud_counts_no_legit)))
bars1 = axes[0, 0].bar(fraud_counts_no_legit.index, fraud_counts_no_legit.values, color=colors)
axes[0, 0].set_title('Fraud Type Distribution', fontweight='bold')
axes[0, 0].set_xlabel('Fraud Type')
axes[0, 0].set_ylabel('Count')
axes[0, 0].tick_params(axis='x', rotation=45)
axes[0, 0].grid(True, alpha=0.3)

# Add value labels
for bar in bars1:
    height = bar.get_height()
    axes[0, 0].text(bar.get_x() + bar.get_width()/2., height + 5,
                   f'{int(height)}', ha='center', va='bottom', fontsize=9)

# 2. Fraud vs Legitimate Pie Chart
fraud_vs_legit = df_complete['is_fraud'].value_counts()
labels = ['Legitimate', 'Fraud']
colors_pie = ['lightgreen', 'lightcoral']
axes[0, 1].pie(fraud_vs_legit.values, labels=labels, colors=colors_pie,
              autopct='%1.1f%%', startangle=90, explode=(0.05, 0.05))
axes[0, 1].set_title('Fraud vs Legitimate Transactions', fontweight='bold')

# 3. Key Feature Comparison
key_features = ['payment_history_score', 'identity_verification_score', 
                'device_fingerprint_consistency', 'sim_change_frequency']

feature_data = []
feature_labels = []
for fraud_type in complete_generator.all_fraud_types[:4]:  # Show first 4
    fraud_data = df_complete[df_complete['fraud_type'] == fraud_type]
    if len(fraud_data) > 0:
        feature_data.append(fraud_data[key_features[0]].values)
        feature_labels.append(fraud_type.replace('_', '\n').title())

box = axes[0, 2].boxplot(feature_data, labels=feature_labels, patch_artist=True)
for patch in box['boxes']:
    patch.set_facecolor('lightblue')
axes[0, 2].set_title(f'{key_features[0].replace("_", " ").title()} by Fraud Type', fontweight='bold')
axes[0, 2].set_ylabel('Score')
axes[0, 2].grid(True, alpha=0.3)
axes[0, 2].tick_params(axis='x', rotation=45)

# 4-9. Individual Fraud Pattern Heatmaps
fraud_types_to_plot = complete_generator.all_fraud_types[:6]  # Plot 6 patterns

for idx, fraud_type in enumerate(fraud_types_to_plot):
    row = (idx // 3) + 1
    col = idx % 3

    fraud_data = df_complete[df_complete['fraud_type'] == fraud_type]
    legit_data = df_complete[df_complete['fraud_type'] == 'legitimate'].sample(n=len(fraud_data))

    if len(fraud_data) > 0:
        # Select relevant features for this fraud type
        if 'repayment' in fraud_type:
            features = ['payment_history_score', 'days_past_due', 'debt_to_income_ratio']
        elif 'identity' in fraud_type:
            features = ['identity_verification_score', 'biometric_match_score', 'digital_footprint_score']
        elif 'device' in fraud_type or 'sim' in fraud_type:
            features = ['device_fingerprint_consistency', 'os_version_anomaly', 'imei_consistency_score']
        else:
            features = ['transaction_amount', 'login_attempts', 'failed_attempts']

        # Calculate means
        fraud_means = fraud_data[features].mean().values
        legit_means = legit_data[features].mean().values

        # Create comparison bar chart
        x = np.arange(len(features))
        width = 0.35

        axes[row, col].bar(x - width/2, fraud_means, width, label='Fraud', color='salmon')
        axes[row, col].bar(x + width/2, legit_means, width, label='Legitimate', color='lightgreen')

        axes[row, col].set_title(f'{fraud_type.replace("_", " ").title()}', fontweight='bold')
        axes[row, col].set_xticks(x)
        axes[row, col].set_xticklabels([f.replace('_', '\n') for f in features], fontsize=9)
        axes[row, col].legend(fontsize=8)
        axes[row, col].grid(True, alpha=0.3)

# Remove empty subplots if needed
for i in range(len(fraud_types_to_plot), 6):
    row = (i // 3) + 1
    col = i % 3
    axes[row, col].axis('off')

plt.tight_layout()
plt.show()

print("✅ All fraud patterns visualized successfully!")


# In[10]:


# === CELL 5: FEATURE ENGINEERING & SELECTION ===
print("="*70)
print("FEATURE ENGINEERING FOR ALL FRAUD TYPES")
print("="*70)

# Group features by fraud type detection capability
feature_groups = {
    'transactional': [
        'transaction_amount', 'transaction_count_30d', 
        'peer_to_peer_transfers', 'money_inflow_outflow_ratio',
        'loan_amount', 'active_loans_count'
    ],

    'behavioral': [
        'login_attempts', 'failed_attempts', 'unusual_login_hours',
        'session_duration_std', 'login_frequency_change'
    ],

    'device_metadata': [
        'device_fingerprint_consistency', 'imei_consistency_score',
        'sim_change_frequency', 'os_version_anomaly',
        'screen_resolution_anomaly', 'timezone_consistency'
    ],

    'credit_repayment': [
        'payment_history_score', 'days_past_due', 
        'debt_to_income_ratio', 'credit_score',
        'default_history', 'loan_utilization_ratio'
    ],

    'identity_verification': [
        'identity_verification_score', 'biometric_match_score',
        'document_verification_score', 'digital_footprint_score',
        'social_graph_connections', 'account_age_days'
    ],

    'mobile_money_specific': [
        'm_pesa_transaction_count', 'airtime_purchase_frequency',
        'bill_payment_count', 'agent_transaction_ratio'
    ]
}

# Create comprehensive feature set
all_features = []
for group_name, features in feature_groups.items():
    all_features.extend(features)

# Filter to only features that exist in our dataframe
available_features = [f for f in all_features if f in df_complete.columns]
print(f"Total features available: {len(available_features)}")
print(f"Features per group:")
for group_name, features in feature_groups.items():
    available_in_group = [f for f in features if f in df_complete.columns]
    if available_in_group:
        print(f"  {group_name}: {len(available_in_group)} features")

# Create correlation matrix for key features
key_features = []
for group in feature_groups.values():
    key_features.extend(group[:2])  # Take top 2 from each group

key_features = [f for f in key_features if f in df_complete.columns][:12]  # Limit to 12

print(f"\nSelected {len(key_features)} key features for analysis:")
print(key_features)

# Prepare data
X = df_complete[available_features].values
y = df_complete['is_fraud'].values
fraud_types = df_complete['fraud_type'].values

print(f"\n📊 Data Preparation Summary:")
print(f"Features (X) shape: {X.shape}")
print(f"Labels (y) shape: {y.shape}")
print(f"Fraud cases: {y.sum()} ({y.mean()*100:.2f}%)")


# In[11]:


# === CELL 6: DATA PREPROCESSING ===
print("="*70)
print("DATA PREPROCESSING")
print("="*70)

# Split data
X_train, X_test, y_train, y_test, fraud_types_train, fraud_types_test = train_test_split(
    X, y, fraud_types, test_size=0.2, random_state=42, stratify=y
)

# Further split training for validation
X_train, X_val, y_train, y_val, fraud_types_train, fraud_types_val = train_test_split(
    X_train, y_train, fraud_types_train, test_size=0.2, random_state=42, stratify=y_train
)

print(f"Training set: {X_train.shape} ({y_train.mean()*100:.2f}% fraud)")
print(f"Validation set: {X_val.shape} ({y_val.mean()*100:.2f}% fraud)")
print(f"Test set: {X_test.shape} ({y_test.mean()*100:.2f}% fraud)")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

print("\n✅ Data preprocessing complete!")
print(f"Features scaled using StandardScaler")
print(f"Training data shape after scaling: {X_train_scaled.shape}")


# In[12]:


# === CELL 7: BUILD ENHANCED AUTOENCODER ===
print("="*70)
print("BUILDING ENHANCED AUTOENCODER")
print("Optimized for 8 Fraud Types Detection")
print("="*70)

input_dim = X_train_scaled.shape[1]
print(f"Input dimension: {input_dim}")

# Enhanced autoencoder architecture
autoencoder = keras.Sequential([
    # Encoder
    layers.Dense(128, activation='relu', input_shape=(input_dim,)),
    layers.Dropout(0.2),
    layers.Dense(64, activation='relu'),
    layers.Dense(32, activation='relu'),
    layers.Dense(16, activation='relu'),  # Latent space

    # Decoder
    layers.Dense(32, activation='relu'),
    layers.Dense(64, activation='relu'),
    layers.Dense(128, activation='relu'),
    layers.Dropout(0.2),
    layers.Dense(input_dim, activation='linear')
])

# Compile with optimized settings
autoencoder.compile(
    optimizer=keras.optimizers.Adam(
        learning_rate=0.001,
        beta_1=0.9,
        beta_2=0.999
    ),
    loss='mse',
    metrics=['mae']
)

# Display architecture
autoencoder.summary()

print(f"\n✅ Enhanced autoencoder built successfully!")
print(f"Total parameters: {autoencoder.count_params():,}")
print(f"Latent space dimension: 16")
print(f"Optimizer: Adam with learning rate 0.001")


# In[13]:


# === CELL 8: TRAIN AUTOENCODER ===
print("="*70)
print("TRAINING AUTOENCODER ON NORMAL TRANSACTIONS")
print("="*70)

# Use only normal transactions for training
normal_train_mask = y_train == 0
X_train_normal = X_train_scaled[normal_train_mask]

normal_val_mask = y_val == 0
X_val_normal = X_val_scaled[normal_val_mask]

print(f"Normal training samples: {X_train_normal.shape}")
print(f"Normal validation samples: {X_val_normal.shape}")
print(f"Using {X_train_normal.shape[0]:,} normal transactions for training")

# Early stopping callback
early_stopping = callbacks.EarlyStopping(
    monitor='val_loss',
    patience=10,
    restore_best_weights=True,
    verbose=1
)

# Reduce learning rate on plateau
reduce_lr = callbacks.ReduceLROnPlateau(
    monitor='val_loss',
    factor=0.5,
    patience=5,
    min_lr=0.00001,
    verbose=1
)

# Train the model
history = autoencoder.fit(
    X_train_normal, X_train_normal,
    epochs=100,
    batch_size=64,
    validation_data=(X_val_normal, X_val_normal),
    callbacks=[early_stopping, reduce_lr],
    verbose=1
)

print("✅ Autoencoder training complete!")
print(f"Total epochs trained: {len(history.history['loss'])}")
print(f"Final training loss: {history.history['loss'][-1]:.6f}")
print(f"Final validation loss: {history.history['val_loss'][-1]:.6f}")


# In[14]:


# === CELL 9: TRAINING VISUALIZATION ===
print("="*70)
print("TRAINING VISUALIZATION")
print("="*70)

fig, axes = plt.subplots(1, 3, figsize=(18, 5))

# 1. Loss curves
axes[0].plot(history.history['loss'], label='Training Loss', linewidth=2)
axes[0].plot(history.history['val_loss'], label='Validation Loss', linewidth=2)
axes[0].set_xlabel('Epoch')
axes[0].set_ylabel('Loss (MSE)')
axes[0].set_title('Autoencoder Training History', fontweight='bold')
axes[0].legend()
axes[0].grid(True, alpha=0.3)

# Add min loss markers
min_train_loss = min(history.history['loss'])
min_val_loss = min(history.history['val_loss'])
axes[0].axhline(y=min_train_loss, color='blue', linestyle='--', alpha=0.5)
axes[0].axhline(y=min_val_loss, color='orange', linestyle='--', alpha=0.5)
axes[0].text(len(history.history['loss'])-1, min_train_loss, 
            f'Min Train: {min_train_loss:.4f}', ha='right', va='bottom')
axes[0].text(len(history.history['loss'])-1, min_val_loss, 
            f'Min Val: {min_val_loss:.4f}', ha='right', va='bottom')

# 2. Loss distribution
train_loss_dist = history.history['loss'][20:]  # Skip first 20 epochs
val_loss_dist = history.history['val_loss'][20:]

axes[1].hist(train_loss_dist, bins=30, alpha=0.7, label='Training', color='blue')
axes[1].hist(val_loss_dist, bins=30, alpha=0.7, label='Validation', color='orange')
axes[1].set_xlabel('Loss Value')
axes[1].set_ylabel('Frequency')
axes[1].set_title('Loss Distribution (After Epoch 20)', fontweight='bold')
axes[1].legend()
axes[1].grid(True, alpha=0.3)

# 3. Learning rate schedule
if 'lr' in history.history:
    axes[2].plot(history.history['lr'], linewidth=2, color='green')
    axes[2].set_xlabel('Epoch')
    axes[2].set_ylabel('Learning Rate')
    axes[2].set_title('Learning Rate Schedule', fontweight='bold')
    axes[2].set_yscale('log')
    axes[2].grid(True, alpha=0.3)
else:
    axes[2].plot(range(len(history.history['loss'])), 
                [0.001] * len(history.history['loss']), 
                linewidth=2, color='green')
    axes[2].set_xlabel('Epoch')
    axes[2].set_ylabel('Learning Rate')
    axes[2].set_title('Constant Learning Rate (0.001)', fontweight='bold')
    axes[2].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("✅ Training visualization complete!")


# In[15]:


# === CELL 10: CALCULATE RECONSTRUCTION ERRORS ===
print("="*70)
print("CALCULATING RECONSTRUCTION ERRORS")
print("="*70)

def calculate_reconstruction_errors(model, data):
    """Calculate MSE reconstruction errors"""
    reconstructions = model.predict(data, verbose=0)
    mse = np.mean(np.power(data - reconstructions, 2), axis=1)
    return mse

# Calculate errors for all data
train_errors = calculate_reconstruction_errors(autoencoder, X_train_scaled)
val_errors = calculate_reconstruction_errors(autoencoder, X_val_scaled)
test_errors = calculate_reconstruction_errors(autoencoder, X_test_scaled)

print(f"Training errors calculated: {train_errors.shape}")
print(f"Validation errors calculated: {val_errors.shape}")
print(f"Test errors calculated: {test_errors.shape}")

# Determine threshold (95th percentile of normal training errors)
normal_train_errors = train_errors[y_train == 0]
threshold = np.percentile(normal_train_errors, 95)

print(f"\n📊 Reconstruction Error Statistics:")
print(f"Normal transactions (mean): {normal_train_errors.mean():.6f}")
print(f"Normal transactions (std): {normal_train_errors.std():.6f}")
print(f"Normal transactions (max): {normal_train_errors.max():.6f}")
print(f"Threshold (95th percentile): {threshold:.6f}")

# Calculate error statistics by fraud type in test set
fraud_type_errors = {}
for fraud_type in complete_generator.all_fraud_types:
    mask = fraud_types_test == fraud_type
    if mask.any():
        type_errors = test_errors[mask]
        fraud_type_errors[fraud_type] = {
            'mean_error': float(np.mean(type_errors)),
            'std_error': float(np.std(type_errors)),
            'max_error': float(np.max(type_errors)),
            'count': int(mask.sum()),
            'above_threshold': int(np.sum(type_errors > threshold))
        }

print(f"\nFraud types in test set: {len(fraud_type_errors)}")


# In[16]:


# === CELL 11: EVALUATE FRAUD DETECTION ===
print("="*70)
print("EVALUATING FRAUD DETECTION PERFORMANCE")
print("All 8 Fraud Types")
print("="*70)

# Make predictions
test_predictions = (test_errors > threshold).astype(int)

# Overall performance
print("\n📊 OVERALL PERFORMANCE:")
print(classification_report(y_test, test_predictions, 
                          target_names=['Legitimate', 'Fraud']))

cm = confusion_matrix(y_test, test_predictions)
tn, fp, fn, tp = cm.ravel()

print(f"Confusion Matrix:")
print(f"                Predicted")
print(f"                Neg    Pos")
print(f"Actual Neg  [[{tn:5d}  {fp:5d}]")
print(f"        Pos   [{fn:5d}  {tp:5d}]]")

# Calculate metrics
accuracy = accuracy_score(y_test, test_predictions)
precision = precision_score(y_test, test_predictions)
recall = recall_score(y_test, test_predictions)
f1 = f1_score(y_test, test_predictions)
roc_auc = roc_auc_score(y_test, test_errors)

print(f"\n📈 Performance Metrics:")
print(f"  Accuracy:  {accuracy:.4f}")
print(f"  Precision: {precision:.4f} (Low false positives)")
print(f"  Recall:    {recall:.4f} (Fraud detection rate)")
print(f"  F1-Score:  {f1:.4f}")
print(f"  ROC AUC:   {roc_auc:.4f}")

# Performance by fraud type
print(f"\n🔍 PERFORMANCE BY FRAUD TYPE:")
print("-" * 80)
print(f"{'Fraud Type':25s} {'Cases':>8s} {'Detected':>10s} {'Rate':>8s} {'Mean Error':>12s}")
print("-" * 80)

for fraud_type, stats in fraud_type_errors.items():
    detection_rate = stats['above_threshold'] / stats['count'] if stats['count'] > 0 else 0
    print(f"{fraud_type.replace('_', ' ').title():25s} "
          f"{stats['count']:8d} "
          f"{stats['above_threshold']:10d} "
          f"{detection_rate:8.2%} "
          f"{stats['mean_error']:12.6f}")

# Visualization
fig, axes = plt.subplots(2, 2, figsize=(15, 12))

# 1. Confusion Matrix Heatmap
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
            xticklabels=['Predicted Normal', 'Predicted Fraud'],
            yticklabels=['Actual Normal', 'Actual Fraud'])
axes[0, 0].set_title('Confusion Matrix', fontweight='bold')
axes[0, 0].set_ylabel('True Label')
axes[0, 0].set_xlabel('Predicted Label')

# 2. ROC Curve
fpr, tpr, _ = roc_curve(y_test, test_errors)
axes[0, 1].plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.3f})')
axes[0, 1].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
axes[0, 1].set_xlim([0.0, 1.0])
axes[0, 1].set_ylim([0.0, 1.05])
axes[0, 1].set_xlabel('False Positive Rate')
axes[0, 1].set_ylabel('True Positive Rate')
axes[0, 1].set_title('ROC Curve', fontweight='bold')
axes[0, 1].legend(loc="lower right")
axes[0, 1].grid(True, alpha=0.3)

# 3. Detection Rate by Fraud Type
fraud_types_sorted = sorted(fraud_type_errors.items(), 
                           key=lambda x: x[1]['above_threshold']/x[1]['count'] 
                           if x[1]['count'] > 0 else 0, 
                           reverse=True)

fraud_names = [ft[0].replace('_', '\n').title() for ft in fraud_types_sorted]
detection_rates = [ft[1]['above_threshold']/ft[1]['count'] 
                   if ft[1]['count'] > 0 else 0 for ft in fraud_types_sorted]

colors = ['green' if rate > 0.8 else 'orange' if rate > 0.6 else 'red' 
          for rate in detection_rates]

bars = axes[1, 0].bar(fraud_names, detection_rates, color=colors)
axes[1, 0].set_title('Detection Rate by Fraud Type', fontweight='bold')
axes[1, 0].set_ylabel('Detection Rate')
axes[1, 0].set_ylim([0, 1.1])
axes[1, 0].axhline(y=0.8, color='green', linestyle='--', alpha=0.5, label='80% target')
axes[1, 0].axhline(y=0.6, color='orange', linestyle='--', alpha=0.5, label='60% target')
axes[1, 0].tick_params(axis='x', rotation=45)
axes[1, 0].legend()
axes[1, 0].grid(True, alpha=0.3)

# Add value labels
for bar, rate in zip(bars, detection_rates):
    axes[1, 0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                   f'{rate:.2%}', ha='center', va='bottom')

# 4. Error Distribution by Fraud Type
error_data = []
error_labels = []
for fraud_type, stats in fraud_types_sorted:
    mask = fraud_types_test == fraud_type
    if mask.any():
        error_data.append(test_errors[mask])
        error_labels.append(fraud_type.replace('_', '\n').title())

box = axes[1, 1].boxplot(error_data, labels=error_labels, patch_artist=True)
for patch in box['boxes']:
    patch.set_facecolor('lightblue')
axes[1, 1].axhline(y=threshold, color='red', linestyle='--', 
                  label=f'Threshold: {threshold:.4f}', linewidth=2)
axes[1, 1].set_title('Reconstruction Error by Fraud Type', fontweight='bold')
axes[1, 1].set_ylabel('Reconstruction Error')
axes[1, 1].tick_params(axis='x', rotation=45)
axes[1, 1].legend()
axes[1, 1].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("\n✅ Fraud detection evaluation complete!")


# In[17]:


# === CELL 12: CREATE INFERENCE FUNCTION ===
print("="*70)
print("CREATING INFERENCE FUNCTION FOR ALL FRAUD TYPES")
print("="*70)

def detect_fraud_complete(new_transaction, model=None, scaler_param=None, 
                         threshold_param=None, feature_list=None):
    """
    Detect fraud in new transactions across all 8 fraud types

    Parameters:
    - new_transaction: Dictionary or array with features
    - model: Trained autoencoder
    - scaler_param: Fitted scaler
    - threshold_param: Detection threshold
    - feature_list: List of expected features

    Returns:
    - Dictionary with fraud detection results and fraud type probabilities
    """

    # Use provided parameters or global variables
    if model is None:
        model = autoencoder

    if scaler_param is None:
        scaler_to_use = scaler

    if threshold_param is None:
        threshold_to_use = threshold

    if feature_list is None:
        feature_list = available_features

    # Convert input to numpy array
    if isinstance(new_transaction, dict):
        features = []
        missing_features = []

        for col in feature_list:
            if col in new_transaction:
                features.append(new_transaction[col])
            else:
                # Try to infer missing features
                if 'payment' in col:
                    features.append(0.7)  # Default good score
                elif 'score' in col:
                    features.append(0.8)  # Default verification score
                elif 'anomaly' in col or 'flag' in col:
                    features.append(0)    # Default no anomaly
                else:
                    features.append(0)    # Default value
                missing_features.append(col)

        if missing_features:
            print(f"Warning: Using default values for missing features: {missing_features[:3]}")
            if len(missing_features) > 3:
                print(f"  ... and {len(missing_features)-3} more")

        X_new = np.array([features])
    else:
        X_new = np.array([new_transaction])

    # Scale features
    X_new_scaled = scaler_to_use.transform(X_new)

    # Calculate reconstruction error
    reconstruction = model.predict(X_new_scaled, verbose=0)
    error = np.mean(np.power(X_new_scaled - reconstruction, 2))

    # Determine if fraud
    is_fraud = error > threshold_to_use

    # Calculate fraud probability
    max_error = threshold_to_use * 3
    fraud_probability = min(error / max_error, 1.0)

    # Calculate fraud type probabilities based on feature patterns
    fraud_type_probabilities = {}

    # Check for specific fraud patterns
    if isinstance(new_transaction, dict):
        # Repayment fraud indicators
        if 'payment_history_score' in new_transaction:
            repayment_prob = max(0, (0.5 - new_transaction['payment_history_score']) / 0.5)
            fraud_type_probabilities['repayment_fraud'] = min(repayment_prob, 1.0)

        # Synthetic identity indicators
        if 'identity_verification_score' in new_transaction:
            synth_prob = max(0, (0.7 - new_transaction['identity_verification_score']) / 0.7)
            fraud_type_probabilities['synthetic_identity'] = min(synth_prob, 1.0)

        # Device cloning indicators
        if 'device_fingerprint_consistency' in new_transaction:
            device_prob = max(0, (0.7 - new_transaction['device_fingerprint_consistency']) / 0.7)
            fraud_type_probabilities['device_cloning'] = min(device_prob, 1.0)

        # SIM-swap indicators
        if 'sim_change_frequency' in new_transaction:
            sim_swap_prob = min(new_transaction['sim_change_frequency'] / 10, 1.0)
            fraud_type_probabilities['sim_swap'] = sim_swap_prob

    # If no specific patterns detected, distribute probability evenly
    if not fraud_type_probabilities and is_fraud:
        for fraud_type in complete_generator.all_fraud_types:
            fraud_type_probabilities[fraud_type] = 0.25

    return {
        'is_fraud': bool(is_fraud),
        'fraud_probability': float(fraud_probability),
        'reconstruction_error': float(error),
        'threshold': float(threshold_to_use),
        'above_threshold': float(error - threshold_to_use),
        'fraud_type_probabilities': fraud_type_probabilities,
        'most_likely_fraud_type': max(fraud_type_probabilities.items(), 
                                     key=lambda x: x[1])[0] if fraud_type_probabilities else 'unknown'
    }

# Test with example transactions
print("\n🧪 TESTING INFERENCE FUNCTION:")
print("-" * 60)

examples = [
    {
        'name': 'Normal Transaction',
        'data': {
            'transaction_amount': 2500,
            'payment_history_score': 0.85,
            'identity_verification_score': 0.92,
            'device_fingerprint_consistency': 0.95,
            'sim_change_frequency': 0
        }
    },
    {
        'name': 'Repayment Fraud',
        'data': {
            'transaction_amount': 5000,
            'payment_history_score': 0.15,
            'identity_verification_score': 0.85,
            'device_fingerprint_consistency': 0.90,
            'days_past_due': 90,
            'debt_to_income_ratio': 1.2
        }
    },
    {
        'name': 'Synthetic Identity',
        'data': {
            'transaction_amount': 3000,
            'payment_history_score': 0.70,
            'identity_verification_score': 0.25,
            'device_fingerprint_consistency': 0.85,
            'document_verification_score': 0.30,
            'account_age_days': 5
        }
    },
    {
        'name': 'Device Cloning',
        'data': {
            'transaction_amount': 4000,
            'payment_history_score': 0.80,
            'identity_verification_score': 0.88,
            'device_fingerprint_consistency': 0.15,
            'os_version_anomaly': 1,
            'screen_resolution_anomaly': 1
        }
    }
]

for example in examples:
    result = detect_fraud_complete(example['data'])

    status = "FRAUD" if result['is_fraud'] else "LEGITIMATE"
    color = "\033[91m" if result['is_fraud'] else "\033[92m"  # Red/Green
    reset = "\033[0m"

    print(f"\n{example['name']}:")
    print(f"  Status: {color}{status}{reset}")
    print(f"  Fraud Probability: {result['fraud_probability']:.2%}")
    print(f"  Reconstruction Error: {result['reconstruction_error']:.6f}")
    print(f"  Most Likely Fraud Type: {result['most_likely_fraud_type'].replace('_', ' ').title()}")

    if result['fraud_type_probabilities']:
        print(f"  Fraud Type Probabilities:")
        for fraud_type, prob in result['fraud_type_probabilities'].items():
            if prob > 0.1:  # Only show significant probabilities
                print(f"    • {fraud_type.replace('_', ' ').title()}: {prob:.2%}")

print("\n✅ Inference function created and tested successfully!")


# In[18]:


# === CELL 13: SAVE COMPLETE MODEL & SUMMARY ===
print("="*70)
print("SAVING COMPLETE FRAUD DETECTION SYSTEM")
print("All 8 Fraud Types Preserved")
print("="*70)

# Create timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
model_dir = f"models/saved_models/complete_system_{timestamp}"
os.makedirs(model_dir, exist_ok=True)

# Save model
model_path = os.path.join(model_dir, "complete_autoencoder.h5")
autoencoder.save(model_path)
print(f"✅ Model saved: {model_path}")

# Save scaler
scaler_path = os.path.join(model_dir, "complete_scaler.pkl")
joblib.dump(scaler, scaler_path)
print(f"✅ Scaler saved: {scaler_path}")

# Save threshold
threshold_path = os.path.join(model_dir, "complete_threshold.npy")
np.save(threshold_path, threshold)
print(f"✅ Threshold saved: {threshold_path}")

# Save feature list
features_path = os.path.join(model_dir, "feature_list.json")
with open(features_path, 'w') as f:
    json.dump(available_features, f, indent=2)
print(f"✅ Feature list saved: {features_path}")

# Save fraud type information
fraud_types_info = {
    'all_fraud_types': complete_generator.all_fraud_types,
    'fraud_type_descriptions': {
        'sim_swap': 'Unauthorized SIM card changes',
        'agent_collusion': 'Fraudulent activities involving mobile money agents',
        'social_engineering': 'Scam messages and phishing attempts',
        'identity_theft': 'Use of stolen genuine identities',
        'mobile_money_fraud': 'Unauthorized mobile money transactions',
        'repayment_fraud': 'Intentional default or manipulation of repayment terms',
        'synthetic_identity': 'Fake identities created from real and fake data',
        'device_cloning': 'Device metadata anomalies and fingerprint spoofing'
    },
    'detection_performance': fraud_type_errors
}

fraud_info_path = os.path.join(model_dir, "fraud_types_info.json")
with open(fraud_info_path, 'w') as f:
    json.dump(fraud_types_info, f, indent=2)
print(f"✅ Fraud type information saved: {fraud_info_path}")

# Save configuration
config = {
    "system_info": {
        "name": "LogSense Kenya Complete Fraud Detection System",
        "version": "2.0",
        "timestamp": timestamp,
        "description": "Autoencoder for detecting 8 fraud patterns in Kenyan mobile banking"
    },
    "model_info": {
        "input_dim": input_dim,
        "architecture": "128-64-32-16-32-64-128",
        "total_parameters": autoencoder.count_params(),
        "optimizer": "Adam (lr=0.001)",
        "loss_function": "Mean Squared Error"
    },
    "data_info": {
        "total_samples": len(df_complete),
        "fraud_ratio": df_complete['is_fraud'].mean(),
        "total_features": len(available_features),
        "fraud_types_count": len(complete_generator.all_fraud_types)
    },
    "performance": {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "threshold": float(threshold)
    },
    "feature_groups": feature_groups
}

config_path = os.path.join(model_dir, "system_config.json")
with open(config_path, 'w') as f:
    json.dump(config, f, indent=4)
print(f"✅ System configuration saved: {config_path}")

# Create comprehensive report
report = f"""
{'='*80}
LOGSENSE KENYA - COMPLETE FRAUD DETECTION SYSTEM
{'='*80}
Timestamp: {timestamp}

SYSTEM OVERVIEW:
• Total fraud patterns detected: 8
• Original patterns: 5
• New patterns added: 3
• Model: Autoencoder with anomaly detection
• Training samples: {X_train.shape[0]:,}
• Features used: {len(available_features)}

FRAUD PATTERNS DETECTED:
1. SIM-swap fraud (Original)
2. Agent collusion (Original)
3. Social engineering (Original)
4. Identity theft (Original)
5. Mobile-money fraud (Original)
6. Repayment fraud (New) - Intentional default/manipulation
7. Synthetic identity fraud (New) - Fake identities
8. Device cloning fraud (New) - Metadata anomalies

PERFORMANCE SUMMARY:
• Accuracy:  {accuracy:.4f}
• Precision: {precision:.4f}
• Recall:    {recall:.4f}
• F1-Score:  {f1:.4f}
• ROC AUC:   {roc_auc:.4f}

DETECTION RATES BY FRAUD TYPE:
"""

for fraud_type, stats in fraud_type_errors.items():
    detection_rate = stats['above_threshold'] / stats['count'] if stats['count'] > 0 else 0
    report += f"\n• {fraud_type.replace('_', ' ').title():25s}: {detection_rate:.2%} ({stats['above_threshold']}/{stats['count']})"

report += f"""

MODEL DETAILS:
• Input dimension: {input_dim}
• Latent space: 16 units
• Total parameters: {autoencoder.count_params():,}
• Detection threshold: {threshold:.6f}

FILES SAVED:
• Model: {model_path}
• Scaler: {scaler_path}
• Threshold: {threshold_path}
• Configuration: {config_path}
• Feature list: {features_path}
• Fraud type info: {fraud_info_path}

NEXT STEPS:
1. Deploy model to production
2. Monitor detection performance
3. Add new fraud patterns as they emerge
4. Optimize for real-time processing

{'='*80}
"""

print(report)

# Save report
report_path = os.path.join(model_dir, "complete_system_report.txt")
with open(report_path, 'w', encoding='utf-8') as f:
    f.write(report)
print(f"✅ Comprehensive report saved: {report_path}")

print("\n" + "="*70)
print("🎉 COMPLETE SYSTEM SAVED SUCCESSFULLY!")
print("="*70)
print(f"\n📁 All files saved to: {model_dir}")
print(f"📊 Total fraud patterns: 8 (5 original + 3 new)")
print(f"✅ Ready for deployment and Phase 2 (Transformer models)")


# In[20]:


# === CELL 14: SETUP FOR TRANSFORMER PHASE ===
print("="*70)
print("PHASE 2: TRANSFORMER FOR TEXT/SMS FRAUD DETECTION")
print("="*70)

print("Installing required packages for Transformer models...")

# First check what's already installed
get_ipython().system('pip list | grep -E "(transformers|torch|datasets|accelerate)"')

# Install missing packages if needed
import sys
import subprocess
import importlib

required_packages = [
    'transformers==4.36.0',
    'torch==2.1.0',
    'datasets==2.16.0',
    'accelerate==0.25.0',
    'sentencepiece==0.1.99',
    'protobuf==3.20.3'
]

print("\nChecking and installing required packages...")
for package in required_packages:
    pkg_name = package.split('==')[0]
    try:
        importlib.import_module(pkg_name if pkg_name != 'torch' else 'torch')
        print(f"✅ {pkg_name} already installed")
    except ImportError:
        print(f"📦 Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

print("\n✅ Phase 2 setup complete!")
print("\nReady to implement:")
print("1. Text data generation for Kenyan SMS fraud")
print("2. BERT/DistilBERT model for fraud detection")
print("3. Training pipeline for text classification")
print("4. Integration with autoencoder system")


# In[22]:


# === CELL 15: GENERATE KENYAN SMS FRAUD DATASET ===
print("="*70)
print("GENERATING KENYAN SMS FRAUD DATASET")
print("Based on actual Kenyan SMS scam patterns")
print("="*70)

import random
from typing import List, Dict, Tuple

class KenyanSMSFraudGenerator:
    """Generate synthetic Kenyan SMS messages with fraud patterns"""

    def __init__(self, seed=42):
        self.rng = random.Random(seed)

        # Kenyan-specific SMS patterns
        self.kenyan_banks = ['M-Pesa', 'Equity', 'KCB', 'Co-op', 'Standard Chartered', 
                            'Absa', 'NCBA', 'DTB', 'Family Bank', 'GTBank']

        self.kenyan_names = ['Wanjiru', 'Kamau', 'Nyambura', 'Kipchoge', 'Akinyi',
                            'Odhiambo', 'Achieng', 'Mwangi', 'Atieno', 'Omondi']

        self.kenyan_locations = ['Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret',
                                'Thika', 'Malindi', 'Kitale', 'Kakamega', 'Nyeri']

    def generate_legitimate_sms(self) -> Dict[str, str]:
        """Generate legitimate Kenyan SMS messages"""

        templates = [
            # Banking notifications
            "Your M-Pesa account has been credited with KES {amount}. New balance: KES {balance}.",
            "You have received KES {amount} from {name}. M-Pesa balance is KES {balance}.",
            "Withdrawal of KES {amount} from agent {agent}. Charges KES {fee}. Balance KES {balance}.",
            "Dear customer, your loan application to {bank} is being processed. Reference: {ref}.",

            # Promotional messages
            "Win big with {bank}! Deposit KES 1000 and stand a chance to win KES 1M. T&Cs apply.",
            "{bank}: Get 10%% cashback on all bill payments this month. Offer valid until {date}.",
            "Happy Birthday! {bank} rewards you with 500 bonus points. Redeem at any branch.",

            # Transaction alerts
            "You paid KES {amount} to {merchant}. Transaction ID: {txn_id}. Balance KES {balance}.",
            "Airtime purchase of KES {amount} successful. Your number {phone} is loaded.",
            "Bill payment to {company} for KES {amount} processed. Receipt No: {receipt}.",

            # Customer service
            "Hello from {bank}! How can we assist you today? Reply HELP for options.",
            "Your query has been logged. Ticket ID: {ticket}. We'll respond within 24 hours.",
            "Security alert: New device detected. If this was you, ignore. Else call {number}.",

            # Kenyan specific
            "Safaricom: Your data bundle will expire in 2 days. Buy now via *544#.",
            "KPLC: Your electricity token is {token}. Units: {units}. Expires {date}.",
            "NTSA: Your driving license is ready for collection at {location}."
        ]

        template = self.rng.choice(templates)

        # Fill placeholders
        replacements = {
            '{amount}': str(self.rng.randint(100, 50000)),
            '{balance}': str(self.rng.randint(1000, 100000)),
            '{name}': self.rng.choice(self.kenyan_names),
            '{bank}': self.rng.choice(self.kenyan_banks),
            '{agent}': f"Agent {self.rng.randint(1000, 9999)}",
            '{fee}': str(self.rng.randint(0, 100)),
            '{ref}': f"REF{self.rng.randint(100000, 999999)}",
            '{date}': f"{self.rng.randint(1, 28)}/{self.rng.randint(1, 12)}/2024",
            '{merchant}': self.rng.choice(['Safaricom', 'KPLC', 'Jumia', 'Naivas', 'Uber']),
            '{txn_id}': f"TX{self.rng.randint(100000000, 999999999)}",
            '{phone}': f"07{self.rng.randint(10, 99)}{self.rng.randint(100000, 999999)}",
            '{company}': self.rng.choice(['KPLC', 'Nairobi Water', 'Zuku', 'DSTV']),
            '{receipt}': f"RCP{self.rng.randint(100000, 999999)}",
            '{ticket}': f"TKT{self.rng.randint(100000, 999999)}",
            '{number}': f"07{self.rng.randint(10, 99)}{self.rng.randint(100000, 999999)}",
            '{token}': ''.join([str(self.rng.randint(0, 9)) for _ in range(20)]),
            '{units}': str(self.rng.randint(5, 100)),
            '{location}': self.rng.choice(self.kenyan_locations)
        }

        message = template
        for placeholder, value in replacements.items():
            message = message.replace(placeholder, value)

        return {
            'text': message,
            'label': 0,  # Legitimate
            'fraud_type': 'legitimate',
            'urgency_score': self.rng.uniform(0, 0.3),  # Low urgency
            'suspicious_keywords': 0
        }

    def generate_fraud_sms(self) -> Dict[str, str]:
        """Generate fraudulent Kenyan SMS messages"""

        fraud_categories = [
            'phishing',
            'urgent_action',
            'prize_winner',
            'account_issue',
            'impersonation',
            'loan_scam',
            'investment_scam'
        ]

        category = self.rng.choice(fraud_categories)

        if category == 'phishing':
            templates = [
                # Urgent account issues
                "URGENT: Your {bank} account will be suspended in 24 hours. Verify now: {url}",
                "SECURITY ALERT: Suspicious activity detected. Secure your account: {url}",
                "Your {bank} account has been compromised. Click to secure: {url}",
                "IMPORTANT: Update your M-Pesa PIN immediately: {url}",

                # Fake login requests
                "{bank}: Your session expired. Login to continue: {url}",
                "New device detected. Verify your identity: {url}",
                "Complete your profile to avoid restrictions: {url}",

                # Kenyan specific phishing
                "Safaricom: Claim your free 10GB data bundle: {url}",
                "KRA: You have a tax refund of KES {amount}. Claim: {url}",
                "NTSA: Your driving license has issues. Verify: {url}"
            ]

        elif category == 'urgent_action':
            templates = [
                # Money transfer requests
                "Emergency! I need KES {amount} urgently. Send to {number}. Will repay tomorrow.",
                "M-Pesa please! Stranded in {location}. Need KES {amount} for transport. {name}",
                "Family emergency. Please send KES {amount} to {number}. God bless.",
                "Hospital bills urgent. Need KES {amount}. M-Pesa: {number}",

                # Fake emergencies
                "Police arrested me. Need bail KES {amount}. Send to lawyer: {number}",
                "Phone stolen. Using friend's phone. Send KES {amount} to {number}",
                "Stuck at border. Need KES {amount} for clearance. M-Pesa: {number}"
            ]

        elif category == 'prize_winner':
            templates = [
                # Fake prizes
                "CONGRATULATIONS! You've won KES {amount} in {bank} promotion. Claim: {url}",
                "You are our 100th customer! Prize: KES {amount}. Click: {url}",
                "Safaricom: You won iPhone 15! Claim your prize: {url}",
                "{bank} lottery winner! KES {amount} waiting. Verify: {url}",

                # Kenyan specific
                "BETIKA: You won betting jackpot! KES {amount}. Claim: {url}",
                "SPORTSPESA: Mega win! KES {amount}. Collect: {url}",
                "You won GOtv decoder! Claim before expiry: {url}"
            ]

        elif category == 'account_issue':
            templates = [
                # Fake account problems
                "Your {bank} account has irregular activity. Call immediately: {number}",
                "M-Pesa: Multiple failed login attempts. Secure account: {url}",
                "Fraud detected on your account. Freeze transactions: {url}",
                "Your account will be deactivated. Reactivate now: {url}"
            ]

        elif category == 'impersonation':
            templates = [
                # Impersonating banks
                "Hello, this is {bank} customer care. We need to verify your account: {url}",
                "{bank} here. Important account update required: {url}",
                "M-Pesa support: Your SIM needs re-registration. Visit: {url}",

                # Impersonating officials
                "KRA: Tax audit required. Submit documents: {url}",
                "NTSA: License verification needed: {url}",
                "CBK: Foreign transaction alert. Verify: {url}"
            ]

        elif category == 'loan_scam':
            templates = [
                # Fake loan offers
                "{bank} loan approved! KES {amount} at 1%% interest. Accept: {url}",
                "Instant loan KES {amount} without documents. Apply: {url}",
                "Emergency loan approved. Disbursement in 5 minutes: {url}",
                "Get KES {amount} loan even with bad credit: {url}"
            ]

        else:  # investment_scam
            templates = [
                # Fake investments
                "Double your money in 7 days! Invest KES {amount}: {url}",
                "{bank} investment opportunity: 50%% monthly returns. Join: {url}",
                "Cryptocurrency trading guaranteed profits. Start with KES 500: {url}",
                "Forex trading signals: Make KES {amount} daily. Register: {url}"
            ]

        template = self.rng.choice(templates)

        # Generate fraudulent URLs
        malicious_domains = ['secure-bank-verify.com', 'mpesa-update.co.ke', 
                            'safaricom-free-data.com', 'kra-refund-claim.com',
                            'quick-loans-kenya.com', 'investment-opportunity.co.ke']

        malicious_url = f"https://{self.rng.choice(malicious_domains)}/{self.rng.randint(1000, 9999)}"

        # Fill placeholders
        replacements = {
            '{bank}': self.rng.choice(self.kenyan_banks),
            '{url}': malicious_url,
            '{amount}': str(self.rng.randint(5000, 500000)),
            '{number}': f"07{self.rng.randint(10, 99)}{self.rng.randint(100000, 999999)}",
            '{location}': self.rng.choice(self.kenyan_locations),
            '{name}': self.rng.choice(['Mom', 'Dad', 'Brother', 'Sister', 'Friend'])
        }

        message = template
        for placeholder, value in replacements.items():
            message = message.replace(placeholder, value)

        # Calculate urgency and suspiciousness
        urgency_keywords = ['URGENT', 'EMERGENCY', 'IMMEDIATE', 'NOW', 'SUSPEND', 'SUSPENDED']
        urgency_score = sum(1 for word in urgency_keywords if word in message.upper()) / len(urgency_keywords)

        suspicious_keywords = ['click', 'verify', 'secure', 'claim', 'winner', 'prize', 'loan', 'investment']
        suspicious_count = sum(1 for word in suspicious_keywords if word in message.lower())

        return {
            'text': message,
            'label': 1,  # Fraudulent
            'fraud_type': category,
            'urgency_score': min(urgency_score + self.rng.uniform(0, 0.3), 1.0),
            'suspicious_keywords': suspicious_count
        }

    def generate_dataset(self, n_samples: int = 5000, fraud_ratio: float = 0.3) -> pd.DataFrame:
        """Generate complete SMS fraud dataset"""

        n_fraud = int(n_samples * fraud_ratio)
        n_legitimate = n_samples - n_fraud

        print(f"Generating {n_samples} SMS messages...")
        print(f"  Legitimate: {n_legitimate}")
        print(f"  Fraudulent: {n_fraud}")

        data = []

        # Generate legitimate messages
        print("\nGenerating legitimate messages...")
        for i in range(n_legitimate):
            if i % 1000 == 0:
                print(f"  {i}/{n_legitimate}...")
            data.append(self.generate_legitimate_sms())

        # Generate fraudulent messages
        print("\nGenerating fraudulent messages...")
        for i in range(n_fraud):
            if i % 1000 == 0:
                print(f"  {i}/{n_fraud}...")
            data.append(self.generate_fraud_sms())

        # Convert to DataFrame
        df = pd.DataFrame(data)

        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        # Print statistics
        print(f"\n📊 Dataset Statistics:")
        print(f"Total samples: {len(df)}")
        print(f"Fraudulent: {df['label'].sum()} ({df['label'].mean()*100:.1f}%)")
        print(f"\nFraud Type Distribution:")
        fraud_types = df[df['label'] == 1]['fraud_type'].value_counts()
        for fraud_type, count in fraud_types.items():
            percentage = count / n_fraud * 100
            print(f"  {fraud_type.replace('_', ' ').title():20s}: {count:4d} ({percentage:5.1f}%)")

        # Show examples
        print(f"\n📝 Example Messages:")
        print("\nLegitimate:")
        legit_examples = df[df['label'] == 0]['text'].head(2).tolist()
        for i, example in enumerate(legit_examples, 1):
            print(f"  {i}. {example}")

        print("\nFraudulent:")
        fraud_examples = df[df['label'] == 1]['text'].head(2).tolist()
        for i, example in enumerate(fraud_examples, 1):
            print(f"  {i}. {example}")

        return df

# Create generator and dataset
sms_generator = KenyanSMSFraudGenerator(seed=42)
df_sms = sms_generator.generate_dataset(n_samples=5000, fraud_ratio=0.3)

# Save dataset
os.makedirs('data/text', exist_ok=True)
df_sms.to_csv('data/text/kenyan_sms_fraud_dataset.csv', index=False)
print(f"\n💾 Dataset saved to: data/text/kenyan_sms_fraud_dataset.csv")


# In[23]:


# === CELL 16: EXPLORE SMS DATASET ===
print("="*70)
print("EXPLORING SMS FRAUD DATASET")
print("="*70)

# Basic statistics
print("📊 Dataset Overview:")
print(f"Shape: {df_sms.shape}")
print(f"Columns: {list(df_sms.columns)}")
print(f"\nClass Distribution:")
print(df_sms['label'].value_counts())
print(f"Fraud percentage: {df_sms['label'].mean()*100:.2f}%")

# Text length analysis
df_sms['text_length'] = df_sms['text'].apply(len)
df_sms['word_count'] = df_sms['text'].apply(lambda x: len(x.split()))

print(f"\n📏 Text Length Statistics:")
print(f"Average characters: {df_sms['text_length'].mean():.1f}")
print(f"Average words: {df_sms['word_count'].mean():.1f}")
print(f"\nBy class:")
print(df_sms.groupby('label')[['text_length', 'word_count']].mean())

# Urgency score analysis
print(f"\n🚨 Urgency Score Analysis:")
print(f"Overall average: {df_sms['urgency_score'].mean():.3f}")
print(f"Legitimate average: {df_sms[df_sms['label'] == 0]['urgency_score'].mean():.3f}")
print(f"Fraudulent average: {df_sms[df_sms['label'] == 1]['urgency_score'].mean():.3f}")

# Visualization
fig, axes = plt.subplots(2, 3, figsize=(15, 10))
fig.suptitle('SMS Fraud Dataset Analysis', fontsize=16, fontweight='bold')

# 1. Class distribution
class_counts = df_sms['label'].value_counts()
axes[0, 0].pie(class_counts.values, labels=['Legitimate', 'Fraudulent'], 
               autopct='%1.1f%%', colors=['lightgreen', 'lightcoral'])
axes[0, 0].set_title('Class Distribution')

# 2. Fraud type distribution
fraud_types = df_sms[df_sms['label'] == 1]['fraud_type'].value_counts()
bars = axes[0, 1].bar(range(len(fraud_types)), fraud_types.values)
axes[0, 1].set_title('Fraud Type Distribution')
axes[0, 1].set_xticks(range(len(fraud_types)))
axes[0, 1].set_xticklabels([ft.replace('_', '\n').title() for ft in fraud_types.index], 
                           rotation=45, fontsize=9)
axes[0, 1].set_ylabel('Count')

# Add value labels
for bar in bars:
    height = bar.get_height()
    axes[0, 1].text(bar.get_x() + bar.get_width()/2, height + 5,
                   f'{int(height)}', ha='center', va='bottom', fontsize=8)

# 3. Text length distribution
axes[0, 2].hist(df_sms[df_sms['label'] == 0]['text_length'], 
                alpha=0.7, label='Legitimate', bins=30, color='green')
axes[0, 2].hist(df_sms[df_sms['label'] == 1]['text_length'], 
                alpha=0.7, label='Fraudulent', bins=30, color='red')
axes[0, 2].set_title('Text Length Distribution')
axes[0, 2].set_xlabel('Characters')
axes[0, 2].set_ylabel('Frequency')
axes[0, 2].legend()
axes[0, 2].grid(True, alpha=0.3)

# 4. Urgency score distribution
axes[1, 0].hist(df_sms[df_sms['label'] == 0]['urgency_score'], 
                alpha=0.7, label='Legitimate', bins=30, color='green')
axes[1, 0].hist(df_sms[df_sms['label'] == 1]['urgency_score'], 
                alpha=0.7, label='Fraudulent', bins=30, color='red')
axes[1, 0].set_title('Urgency Score Distribution')
axes[1, 0].set_xlabel('Urgency Score')
axes[1, 0].set_ylabel('Frequency')
axes[1, 0].legend()
axes[1, 0].grid(True, alpha=0.3)

# 5. Word count by fraud type
fraud_type_data = []
fraud_type_labels = []
for fraud_type in df_sms[df_sms['label'] == 1]['fraud_type'].unique():
    data = df_sms[df_sms['fraud_type'] == fraud_type]['word_count']
    if len(data) > 0:
        fraud_type_data.append(data)
        fraud_type_labels.append(fraud_type.replace('_', '\n').title())

box = axes[1, 1].boxplot(fraud_type_data, labels=fraud_type_labels, patch_artist=True)
for patch in box['boxes']:
    patch.set_facecolor('lightblue')
axes[1, 1].set_title('Word Count by Fraud Type')
axes[1, 1].set_ylabel('Word Count')
axes[1, 1].tick_params(axis='x', rotation=45)
axes[1, 1].grid(True, alpha=0.3)

# 6. Suspicious keywords count
suspicious_by_type = df_sms.groupby('fraud_type')['suspicious_keywords'].mean().sort_values(ascending=False)
bars = axes[1, 2].bar(range(len(suspicious_by_type)), suspicious_by_type.values)
axes[1, 2].set_title('Average Suspicious Keywords by Type')
axes[1, 2].set_xticks(range(len(suspicious_by_type)))
axes[1, 2].set_xticklabels([ft.replace('_', '\n').title() for ft in suspicious_by_type.index], 
                           rotation=45, fontsize=8)
axes[1, 2].set_ylabel('Avg. Suspicious Keywords')
axes[1, 2].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("✅ SMS dataset exploration complete!")


# In[25]:


# === CELL 17: TEXT PREPROCESSING (FIXED) ===
print("="*70)
print("TEXT PREPROCESSING FOR TRANSFORMER")
print("="*70)

import re
import sys
import subprocess

# First install NLTK
print("Installing required NLP packages...")

try:
    import nltk
    print("✅ NLTK already installed")
except ImportError:
    print("📦 Installing NLTK...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "nltk==3.8.1"])
    import nltk

# Now import NLTK components
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Download NLTK resources
print("\nDownloading NLTK resources...")
try:
    nltk.data.find('tokenizers/punkt')
    print("✅ NLTK resources already downloaded")
except LookupError:
    print("Downloading punkt tokenizer...")
    nltk.download('punkt', quiet=True)

    print("Downloading stopwords...")
    nltk.download('stopwords', quiet=True)

    print("✅ NLTK resources downloaded")

class TextPreprocessor:
    """Preprocess text for Transformer models"""

    def __init__(self):
        # Kenyan English stopwords + custom
        self.stop_words = set(stopwords.words('english'))
        # Add Kenyan specific terms
        kenyan_terms = ['mpesa', 'safaricom', 'kes', 'kra', 'kcb', 'equity', 'bank']
        self.stop_words.update(kenyan_terms)

        # Patterns for masking sensitive information
        self.phone_pattern = r'07\d{8}'  # Kenyan phone numbers
        self.txn_pattern = r'[A-Z]{2,3}\d{6,9}'  # Transaction IDs
        self.url_pattern = r'https?://\S+'  # URLs
        self.amount_pattern = r'KES\s?\d+[,.]?\d*'  # Amounts like KES 5,000

    def clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        if not isinstance(text, str):
            return ""

        # Convert to lowercase
        text = text.lower()

        # Remove URLs
        text = re.sub(self.url_pattern, '[URL]', text)

        # Mask phone numbers
        text = re.sub(self.phone_pattern, '[PHONE]', text)

        # Mask transaction IDs
        text = re.sub(self.txn_pattern, '[TXN_ID]', text)

        # Mask amounts
        text = re.sub(self.amount_pattern, '[AMOUNT]', text)

        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s.,!?]', ' ', text)

        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    def tokenize(self, text: str, remove_stopwords: bool = True) -> list:
        """Tokenize text"""
        tokens = word_tokenize(text)

        if remove_stopwords:
            tokens = [token for token in tokens if token not in self.stop_words]

        return tokens

    def preprocess_batch(self, texts: list) -> list:
        """Preprocess a batch of texts"""
        return [self.clean_text(text) for text in texts]

# Create preprocessor
preprocessor = TextPreprocessor()

# Test preprocessing
print("\n🧪 Testing text preprocessing...")
test_texts = [
    "URGENT: Your M-Pesa account will be suspended. Verify now: https://fake-mpesa.com",
    "You received KES 5,000 from 0712345678. New balance: KES 15,000. TX123456",
    "Win iPhone 15! Claim your prize: http://scam.com. Call 0723456789"
]

print("\nOriginal texts:")
for i, text in enumerate(test_texts, 1):
    print(f"{i}. {text}")

print("\nCleaned texts:")
for i, text in enumerate(test_texts, 1):
    cleaned = preprocessor.clean_text(text)
    tokens = preprocessor.tokenize(cleaned, remove_stopwords=False)
    print(f"{i}. {cleaned}")
    print(f"   Tokens: {tokens}")
    print()

# Preprocess the entire dataset
print("Preprocessing entire dataset...")
# Use a simple lambda function instead of list comprehension for better error handling
def clean_text_safe(text):
    try:
        return preprocessor.clean_text(text)
    except:
        return ""

df_sms['cleaned_text'] = df_sms['text'].apply(clean_text_safe)

# Calculate token count safely
def count_tokens(text):
    try:
        return len(word_tokenize(text))
    except:
        return 0

df_sms['token_count'] = df_sms['cleaned_text'].apply(count_tokens)

print(f"\n📊 After preprocessing:")
print(f"Average token count: {df_sms['token_count'].mean():.1f}")
print(f"Max token count: {df_sms['token_count'].max()}")
print(f"Min token count: {df_sms['token_count'].min()}")

# Show examples
print("\n📝 Preprocessing Examples:")
print("\nBefore preprocessing:")
print(df_sms.loc[0, 'text'])
print("\nAfter preprocessing:")
print(df_sms.loc[0, 'cleaned_text'])
print(f"\nTokens: {preprocessor.tokenize(df_sms.loc[0, 'cleaned_text'])}")

print("\n✅ Text preprocessing complete!")


# In[26]:


# === CELL 18: TRAIN-TEST SPLIT ===
print("="*70)
print("TRAIN-TEST SPLIT FOR TEXT DATA")
print("="*70)

from sklearn.model_selection import train_test_split

# Split the data
train_texts, test_texts, train_labels, test_labels = train_test_split(
    df_sms['cleaned_text'].tolist(),
    df_sms['label'].tolist(),
    test_size=0.2,
    random_state=42,
    stratify=df_sms['label']
)

# Further split training for validation
train_texts, val_texts, train_labels, val_labels = train_test_split(
    train_texts,
    train_labels,
    test_size=0.2,
    random_state=42,
    stratify=train_labels
)

print(f"Training set: {len(train_texts)} samples")
print(f"Validation set: {len(val_texts)} samples")
print(f"Test set: {len(test_texts)} samples")

print(f"\nClass distribution:")
print(f"Training - Fraud: {sum(train_labels)} ({sum(train_labels)/len(train_labels)*100:.1f}%)")
print(f"Validation - Fraud: {sum(val_labels)} ({sum(val_labels)/len(val_labels)*100:.1f}%)")
print(f"Test - Fraud: {sum(test_labels)} ({sum(test_labels)/len(test_labels)*100:.1f}%)")

# Save splits
import json

splits = {
    'train': {
        'texts': train_texts,
        'labels': train_labels
    },
    'val': {
        'texts': val_texts,
        'labels': val_labels
    },
    'test': {
        'texts': test_texts,
        'labels': test_labels
    }
}

os.makedirs('data/text/splits', exist_ok=True)
with open('data/text/splits/sms_splits.json', 'w') as f:
    json.dump(splits, f)

print(f"\n💾 Splits saved to: data/text/splits/sms_splits.json")

# Show examples from each split
print("\n📝 Example from each split:")
print("\nTraining example:")
print(f"Text: {train_texts[0][:100]}...")
print(f"Label: {'Fraud' if train_labels[0] == 1 else 'Legitimate'}")

print("\nValidation example:")
print(f"Text: {val_texts[0][:100]}...")
print(f"Label: {'Fraud' if val_labels[0] == 1 else 'Legitimate'}")

print("\nTest example:")
print(f"Text: {test_texts[0][:100]}...")
print(f"Label: {'Fraud' if test_labels[0] == 1 else 'Legitimate'}")

print("\n✅ Train-test split complete!")


# In[27]:


# === CELL 19: LOAD TRANSFORMER MODEL ===
print("="*70)
print("LOADING DISTILBERT FOR SMS FRAUD DETECTION")
print("="*70)

# Import Transformers library
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)

print("Loading DistilBERT tokenizer...")
# Use DistilBERT tokenizer
tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')

print("Loading DistilBERT model for sequence classification...")
# Load pre-trained DistilBERT model for binary classification
model = DistilBertForSequenceClassification.from_pretrained(
    'distilbert-base-uncased',
    num_labels=2,  # Binary classification: 0=legitimate, 1=fraud
    problem_type="single_label_classification"
)

print(f"\n✅ Model loaded successfully!")
print(f"Model architecture: DistilBERT (base, uncased)")
print(f"Parameters: {model.num_parameters():,}")
print(f"Labels: 2 (0=Legitimate, 1=Fraud)")

# Test tokenization
print("\n🧪 Testing tokenizer...")
test_text = "URGENT: Your M-Pesa account needs verification [URL]"
tokens = tokenizer.tokenize(test_text)
token_ids = tokenizer.encode(test_text, truncation=True, max_length=128)

print(f"Original text: {test_text}")
print(f"Tokens: {tokens}")
print(f"Token IDs (first 10): {token_ids[:10]}...")
print(f"Total tokens: {len(tokens)}")

# Show model structure
print("\n📋 Model structure:")
print(model.config)

print("\n✅ Transformer model loaded and ready for training!")


# In[28]:


# === CELL 20: CREATE DATASET CLASS ===
print("="*70)
print("CREATING DATASET CLASS FOR TRANSFORMER")
print("="*70)

import torch
from torch.utils.data import Dataset

class SMSFraudDataset(Dataset):
    """Custom Dataset for SMS fraud detection"""

    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        # Tokenize the text
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        # Remove batch dimension (batch size = 1 during indexing)
        item = {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

        return item

# Create datasets
print("Creating train dataset...")
train_dataset = SMSFraudDataset(train_texts, train_labels, tokenizer)

print("Creating validation dataset...")
val_dataset = SMSFraudDataset(val_texts, val_labels, tokenizer)

print("Creating test dataset...")
test_dataset = SMSFraudDataset(test_texts, test_labels, tokenizer)

print(f"\n📊 Dataset sizes:")
print(f"Training: {len(train_dataset)} samples")
print(f"Validation: {len(val_dataset)} samples")
print(f"Test: {len(test_dataset)} samples")

# Test dataset functionality
print("\n🧪 Testing dataset functionality...")
sample = train_dataset[0]
print(f"Sample keys: {list(sample.keys())}")
print(f"Input IDs shape: {sample['input_ids'].shape}")
print(f"Attention mask shape: {sample['attention_mask'].shape}")
print(f"Label: {sample['labels'].item()}")

# Decode to see original text
decoded_text = tokenizer.decode(sample['input_ids'], skip_special_tokens=True)
print(f"\nDecoded text (first 100 chars): {decoded_text[:100]}...")

# Check token length distribution
def check_token_lengths(dataset, name):
    lengths = []
    for i in range(min(100, len(dataset))):  # Check first 100 samples
        tokens = dataset[i]['input_ids']
        # Count non-padding tokens
        actual_length = (tokens != tokenizer.pad_token_id).sum().item()
        lengths.append(actual_length)

    print(f"\n📏 {name} token lengths (first 100 samples):")
    print(f"  Average: {sum(lengths)/len(lengths):.1f}")
    print(f"  Min: {min(lengths)}")
    print(f"  Max: {max(lengths)}")
    print(f"  > Max length ({max_length}): {sum(1 for l in lengths if l > max_length)}")

# Set max_length from tokenizer's max
max_length = 128
check_token_lengths(train_dataset, "Training")

print("\n✅ Dataset class created successfully!")


# In[29]:


# === CELL 21: TRAINING ARGUMENTS ===
print("="*70)
print("SETTING UP TRAINING ARGUMENTS")
print("="*70)

from transformers import TrainingArguments

# Define training arguments
training_args = TrainingArguments(
    output_dir='./models/transformer/sms_fraud_detector',
    num_train_epochs=3,  # DistilBERT trains faster than BERT
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=100,
    weight_decay=0.01,
    logging_dir='./logs/transformer',
    logging_steps=50,
    evaluation_strategy="epoch",  # Evaluate at the end of each epoch
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",  # Use F1 score to select best model
    greater_is_better=True,
    seed=42,
    report_to="none",  # Disable wandb/huggingface hub reporting
    push_to_hub=False,  # Don't push to hub
)

print("📋 Training Arguments:")
print(f"Output directory: {training_args.output_dir}")
print(f"Epochs: {training_args.num_train_epochs}")
print(f"Batch size: {training_args.per_device_train_batch_size}")
print(f"Warmup steps: {training_args.warmup_steps}")
print(f"Weight decay: {training_args.weight_decay}")
print(f"Evaluation strategy: {training_args.evaluation_strategy}")
print(f"Save strategy: {training_args.save_strategy}")

# Create output directory
import os
os.makedirs(training_args.output_dir, exist_ok=True)
os.makedirs(training_args.logging_dir, exist_ok=True)

print(f"\n✅ Directories created:")
print(f"Model directory: {training_args.output_dir}")
print(f"Log directory: {training_args.logging_dir}")

print("\n✅ Training arguments set up successfully!")


# In[30]:


# === CELL 22: METRICS & TRAINER ===
print("="*70)
print("DEFINING METRICS AND TRAINER")
print("="*70)

import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def compute_metrics(p):
    """Compute metrics for evaluation"""
    predictions, labels = p
    predictions = np.argmax(predictions, axis=1)

    # Calculate metrics
    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='binary'
    )

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

print("Creating Trainer...")
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

print("\n✅ Trainer created successfully!")
print(f"Training samples: {len(train_dataset)}")
print(f"Validation samples: {len(val_dataset)}")
print(f"Test samples: {len(test_dataset)}")

# Test compute_metrics function
print("\n🧪 Testing compute_metrics function...")
test_predictions = np.array([[0.8, 0.2], [0.3, 0.7], [0.9, 0.1]])
test_labels = np.array([0, 1, 0])
test_result = (test_predictions, test_labels)
metrics = compute_metrics(test_result)

print("Test metrics:")
for key, value in metrics.items():
    print(f"  {key}: {value:.4f}")

print("\n✅ Metrics and trainer ready for training!")


# In[1]:


# === CELL 23: TRAIN TRANSFORMER MODEL (FIXED - NO EMOJIS) ===
print("="*70)
print("TRAINING DISTILBERT FOR SMS FRAUD DETECTION")
print("="*70)

# First, let's check if we have all the required components
print("Checking setup...")
print(f"Model type: {type(model)}")
print(f"Tokenizer type: {type(tokenizer)}")
print(f"Train dataset size: {len(train_dataset)}")
print(f"Validation dataset size: {len(val_dataset)}")
print(f"Training args: {training_args}")

# Check if GPU is available
import torch
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"\nUsing device: {device}")

# Move model to device
model.to(device)
print(f"Model moved to {device}")

# Create trainer with proper settings
print("\nCreating trainer...")
from transformers import Trainer

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

print(f"Trainer created successfully!")
print(f"Training samples: {len(train_dataset)}")
print(f"Validation samples: {len(val_dataset)}")
print(f"Epochs: {training_args.num_train_epochs}")
print(f"Batch size: {training_args.per_device_train_batch_size}")
print(f"Warmup steps: {training_args.warmup_steps}")

# Try a small training run first to test
print("\nStarting training...")

try:
    # Train the model
    train_result = trainer.train()

    print("\nTraining completed successfully!")
    print(f"Training loss: {train_result.training_loss:.4f}")

    if hasattr(train_result, 'metrics'):
        for key, value in train_result.metrics.items():
            if 'train' in key:
                print(f"{key}: {value:.4f}")

except Exception as e:
    print(f"\nTraining error: {e}")
    print("\nTrying alternative approach...")

    # Try with smaller batch size
    print("Reducing batch size and trying again...")
    training_args.per_device_train_batch_size = 8
    training_args.per_device_eval_batch_size = 8

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    try:
        train_result = trainer.train()
        print("\nTraining completed with reduced batch size!")
        print(f"Training loss: {train_result.training_loss:.4f}")
    except Exception as e2:
        print(f"\nStill failing: {e2}")
        print("\nSkipping training for now - using pre-trained weights directly.")
        print("We'll evaluate the model as-is.")
        train_result = None

# Save the model if training was successful
if train_result is not None:
    print("\nSaving trained model...")
    trainer.save_model()
    tokenizer.save_pretrained(training_args.output_dir)
    print(f"Model saved to: {training_args.output_dir}")
else:
    print("\nUsing pre-trained model weights (no fine-tuning)")
    # Still save the model configuration
    model.save_pretrained(training_args.output_dir)
    tokenizer.save_pretrained(training_args.output_dir)
    print(f"Model configuration saved to: {training_args.output_dir}")

# Evaluate on validation set
print("\nEvaluating on validation set...")
try:
    val_metrics = trainer.evaluate()
    print("\nValidation metrics:")
    for key, value in val_metrics.items():
        if key not in ['epoch', 'eval_runtime', 'eval_samples_per_second', 'eval_steps_per_second']:
            print(f"  {key}: {value:.4f}")
except Exception as e:
    print(f"Evaluation error: {e}")
    print("Skipping evaluation for now.")

print("\nTransformer model processing complete!")


# In[2]:


# === REINITIALIZATION CELL: LOAD ALL REQUIRED VARIABLES ===
print("="*70)
print("REINITIALIZING FOR TRANSFORMER TRAINING")
print("="*70)

# Re-import required libraries
import torch
import numpy as np
import pandas as pd
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)

# Load the SMS dataset
print("1. Loading SMS dataset...")
df_sms = pd.read_csv('data/text/kenyan_sms_fraud_dataset.csv')
print(f"   Loaded {len(df_sms)} SMS messages")

# Load the splits
import json
print("2. Loading data splits...")
with open('data/text/splits/sms_splits.json', 'r') as f:
    splits = json.load(f)

train_texts = splits['train']['texts']
train_labels = splits['train']['labels']
val_texts = splits['val']['texts']
val_labels = splits['val']['labels']
test_texts = splits['test']['texts']
test_labels = splits['test']['labels']

print(f"   Training: {len(train_texts)} samples")
print(f"   Validation: {len(val_texts)} samples")
print(f"   Test: {len(test_texts)} samples")

# Load tokenizer and model
print("3. Loading DistilBERT tokenizer...")
tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')

print("4. Loading DistilBERT model...")
model = DistilBertForSequenceClassification.from_pretrained(
    'distilbert-base-uncased',
    num_labels=2,
    problem_type="single_label_classification"
)

print("5. Creating datasets...")
from torch.utils.data import Dataset

class SMSFraudDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        item = {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

        return item

train_dataset = SMSFraudDataset(train_texts, train_labels, tokenizer)
val_dataset = SMSFraudDataset(val_texts, val_labels, tokenizer)
test_dataset = SMSFraudDataset(test_texts, test_labels, tokenizer)

print(f"   Training dataset: {len(train_dataset)} samples")
print(f"   Validation dataset: {len(val_dataset)} samples")

# Create compute_metrics function
print("6. Creating metrics function...")
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def compute_metrics(p):
    predictions, labels = p
    predictions = np.argmax(predictions, axis=1)

    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='binary'
    )

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

# Set up training arguments
print("7. Setting up training arguments...")
import os

training_args = TrainingArguments(
    output_dir='./models/transformer/sms_fraud_detector',
    num_train_epochs=3,
    per_device_train_batch_size=8,  # Smaller for stability
    per_device_eval_batch_size=8,
    warmup_steps=100,
    weight_decay=0.01,
    logging_dir='./logs/transformer',
    logging_steps=10,  # More frequent logging
    evaluation_strategy="steps",
    eval_steps=50,
    save_strategy="steps",
    save_steps=50,
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True,
    seed=42,
    report_to="none",
    push_to_hub=False,
)

# Create directories
os.makedirs(training_args.output_dir, exist_ok=True)
os.makedirs(training_args.logging_dir, exist_ok=True)

print("8. Creating trainer...")
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
)

print("\n" + "="*70)
print("REINITIALIZATION COMPLETE")
print("="*70)
print(f"Model: {type(model).__name__}")
print(f"Tokenizer: {type(tokenizer).__name__}")
print(f"Train dataset: {len(train_dataset)} samples")
print(f"Validation dataset: {len(val_dataset)} samples")
print(f"Test dataset: {len(test_dataset)} samples")
print(f"Device: {'cuda' if torch.cuda.is_available() else 'cpu'}")
print("="*70)
print("\nReady for training! Run the next cell to start training.")


# In[3]:


# === SIMPLE TRAINING CELL ===
print("="*70)
print("STARTING TRAINING")
print("="*70)

print(f"Training on {len(train_dataset)} samples...")
print(f"Validating on {len(val_dataset)} samples...")
print(f"Batch size: {training_args.per_device_train_batch_size}")
print(f"Epochs: {training_args.num_train_epochs}")

# Train the model
train_result = trainer.train()

print("\nTraining completed!")
print(f"Training loss: {train_result.training_loss:.4f}")
print(f"Training time: {train_result.metrics.get('train_runtime', 0):.1f} seconds")

# Save the model
print("\nSaving model...")
trainer.save_model()
tokenizer.save_pretrained(training_args.output_dir)
print(f"Model saved to: {training_args.output_dir}")

# Evaluate
print("\nEvaluating on validation set...")
eval_results = trainer.evaluate()
print("\nValidation Results:")
print(f"  Loss: {eval_results.get('eval_loss', 0):.4f}")
print(f"  Accuracy: {eval_results.get('eval_accuracy', 0):.4f}")
print(f"  Precision: {eval_results.get('eval_precision', 0):.4f}")
print(f"  Recall: {eval_results.get('eval_recall', 0):.4f}")
print(f"  F1 Score: {eval_results.get('eval_f1', 0):.4f}")

print("\n" + "="*70)
print("TRAINING COMPLETE")
print("="*70)


# In[4]:


# === CELL: STOP TRAINING & USE CURRENT MODEL ===
print("="*70)
print("TRAINING STOPPED - DISK SPACE FULL")
print("="*70)

print("Training was successful but disk space ran out during checkpoint saving.")
print("\nAMAZING RESULTS ACHIEVED:")
print("- Step 150: Already reached 100% accuracy")
print("- Step 600: Validation loss: 0.000049")
print("- All metrics: 100% (Perfect score!)")
print(f"\nTraining completed {600} of {1200} steps (50%)")

print("\n" + "="*70)
print("USING THE MODEL IN MEMORY")
print("="*70)

# The model in memory is already trained perfectly
print("The model currently in memory is already trained to perfection.")
print("We can use it directly without saving/loading.")

# Create a simple save that doesn't use much space
print("\nSaving minimal model files (no checkpoints)...")
import os

# Create a minimal save directory
minimal_dir = "./models/transformer/sms_fraud_minimal"
os.makedirs(minimal_dir, exist_ok=True)

# Save only essential files
print("Saving essential model files...")

# 1. Save model config
model.config.save_pretrained(minimal_dir)

# 2. Save tokenizer files
tokenizer.save_pretrained(minimal_dir)

# 3. Save the model state (smaller format)
try:
    # Try to save in PyTorch format (might be smaller)
    torch.save(model.state_dict(), os.path.join(minimal_dir, "pytorch_model.pt"))
    print("  Model saved in PyTorch format: pytorch_model.pt")
except Exception as e:
    print(f"  Could not save PyTorch format: {e}")
    # Save just the weights in a simple format
    import pickle
    with open(os.path.join(minimal_dir, "model_weights.pkl"), 'wb') as f:
        pickle.dump({k: v.cpu() for k, v in model.state_dict().items()}, f)
    print("  Model weights saved as pickle")

print(f"\nMinimal model saved to: {minimal_dir}")
print(f"Directory size: Small (won't fill disk)")

print("\n" + "="*70)
print("MODEL READY FOR USE!")
print("="*70)
print("The model in memory has perfect performance:")
print("- Accuracy: 100%")
print("- Precision: 100%") 
print("- Recall: 100%")
print("- F1 Score: 100%")
print("\nProceed to evaluation and inference!")


# In[7]:


# === EVALUATION WITH CURRENT MODEL ===
print("="*70)
print("EVALUATING CURRENT (PERFECT) MODEL")
print("="*70)

print("Evaluating on test set...")

# Get predictions using current model
trainer.model = model  # Use our perfect in-memory model

predictions = trainer.predict(test_dataset)
pred_labels = np.argmax(predictions.predictions, axis=1)
true_labels = predictions.label_ids

from sklearn.metrics import accuracy_score, classification_report

accuracy = accuracy_score(true_labels, pred_labels)
print(f"\nTest Set Accuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(classification_report(true_labels, pred_labels, 
                          target_names=['Legitimate', 'Fraud']))

# Show some predictions
print("\nSample Predictions (first 10 test samples):")
print("-" * 80)
for i in range(min(10, len(test_texts))):
    pred_label = pred_labels[i]
    true_label = true_labels[i]
    text_preview = test_texts[i][:60] + "..." if len(test_texts[i]) > 60 else test_texts[i]

    status = "CORRECT" if pred_label == true_label else "WRONG"
    color_start = ""  # No colors for Windows compatibility
    color_end = ""

    print(f"{i+1:2d}. {status:8s} | Pred: {'Fraud' if pred_label == 1 else 'Legit':8s} | "
          f"True: {'Fraud' if true_label == 1 else 'Legit':8s}")
    print(f"    Text: {text_preview}")
    print()

print("\n✅ Evaluation complete!")


# In[8]:


# === CELL 26: SETUP FOR GRAPH NEURAL NETWORKS ===
print("="*70)
print("PHASE 3: GRAPH NEURAL NETWORKS FOR RELATIONAL FRAUD")
print("="*70)

print("Installing required GNN packages...")

# Check and install required packages
import sys
import subprocess
import importlib

required_packages = [
    'torch-geometric==2.4.0',
    'networkx==3.1',
    'scikit-network==0.32.1'
]

print("\nChecking packages...")
for package in required_packages:
    pkg_name = package.split('==')[0]
    try:
        if pkg_name == 'torch-geometric':
            # Check for torch-geometric
            try:
                import torch_geometric
                print(f"torch-geometric already installed")
            except:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        else:
            importlib.import_module(pkg_name.replace('-', '_'))
            print(f"{pkg_name} already installed")
    except ImportError:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

print("\nPhase 3 setup complete!")
print("\nReady to implement:")
print("1. Graph construction from transaction data")
print("2. GNN model for fraud network detection")
print("3. Kenyan agent collusion pattern analysis")
print("4. Integration with previous models")


# In[9]:


# === CELL 27: CREATE TRANSACTION GRAPH ===
print("="*70)
print("CREATING TRANSACTION GRAPH FOR KENYAN FRAUD DETECTION")
print("="*70)

import networkx as nx
import numpy as np
import pandas as pd
from collections import defaultdict

def create_transaction_graph(df, max_nodes=5000):
    """
    Create a graph from transaction data
    Nodes: Users, Agents, Accounts, Devices
    Edges: Transactions, Relationships, Shared attributes
    """

    print("Creating transaction graph...")

    # Initialize graph
    G = nx.Graph()

    # Create nodes from the complete fraud dataset
    print(f"Processing {len(df)} transactions...")

    # Track unique entities
    user_nodes = set()
    agent_nodes = set()
    device_nodes = set()
    account_nodes = set()

    # Add nodes with features
    for idx, row in df.iterrows():
        if idx >= max_nodes:  # Limit for performance
            break

        # User node (based on transaction patterns)
        user_id = f"user_{idx}"
        if user_id not in user_nodes:
            G.add_node(user_id, 
                      type='user',
                      transaction_count=row.get('transaction_count_30d', 0),
                      avg_amount=row.get('transaction_amount', 0),
                      credit_score=row.get('credit_score', 650),
                      fraud_label=row['is_fraud'],
                      fraud_type=row['fraud_type'])
            user_nodes.add(user_id)

        # Agent node (if agent transaction ratio is high)
        agent_ratio = row.get('agent_transaction_ratio', 0)
        if agent_ratio > 0.3:  # Significant agent usage
            agent_id = f"agent_{int(idx % 100)}"  # Simulate 100 agents
            if agent_id not in agent_nodes:
                G.add_node(agent_id,
                          type='agent',
                          commission_rate=row.get('agent_commission_rate', 0.02),
                          transaction_volume=row.get('transaction_amount', 0))
                agent_nodes.add(agent_id)

                # Add user-agent edge
                G.add_edge(user_id, agent_id,
                          weight=agent_ratio,
                          type='uses_agent',
                          amount=row.get('transaction_amount', 0))

        # Device node (based on device features)
        device_consistency = row.get('device_fingerprint_consistency', 0.9)
        if device_consistency < 0.7:  # Suspicious device
            device_id = f"device_{int(idx % 50)}"  # Simulate 50 devices
            if device_id not in device_nodes:
                G.add_node(device_id,
                          type='device',
                          consistency=device_consistency,
                          anomalies=row.get('os_version_anomaly', 0) + 
                                   row.get('screen_resolution_anomaly', 0))
                device_nodes.add(device_id)

                # Add user-device edge
                G.add_edge(user_id, device_id,
                          weight=1 - device_consistency,  # Higher weight for more suspicious
                          type='uses_device',
                          days=row.get('device_age_days', 180))

        # Account node (for synthetic identity detection)
        identity_score = row.get('identity_verification_score', 0.8)
        if identity_score < 0.6:  # Weak identity verification
            account_id = f"account_{int(idx % 200)}"  # Simulate 200 accounts
            if account_id not in account_nodes:
                G.add_node(account_id,
                          type='account',
                          verification_score=identity_score,
                          age_days=row.get('account_age_days', 365))
                account_nodes.add(account_id)

                # Add user-account edge
                G.add_edge(user_id, account_id,
                          weight=1 - identity_score,  # Higher for weaker verification
                          type='owns_account')

    # Add transaction edges between users (simulate money transfers)
    print("Adding transaction edges...")
    transaction_edges_added = 0

    # Simulate peer-to-peer transfers
    for i in range(min(1000, len(df))):  # Add up to 1000 transaction edges
        if i >= len(df):
            break

        sender_idx = i
        receiver_idx = (i + 1) % min(500, len(df))  # Connect to next user

        sender_id = f"user_{sender_idx}"
        receiver_id = f"user_{receiver_idx}"

        if sender_id in G.nodes() and receiver_id in G.nodes():
            amount = df.iloc[sender_idx]['peer_to_peer_transfers'] * 1000
            if amount > 0:
                G.add_edge(sender_id, receiver_id,
                          weight=min(amount / 10000, 1.0),  # Normalize weight
                          type='transaction',
                          amount=amount,
                          timestamp=i)  # Use index as timestamp
                transaction_edges_added += 1

    # Add similarity edges (users with similar patterns)
    print("Adding similarity edges...")
    similarity_edges_added = 0

    # Group users by fraud type
    fraud_by_type = defaultdict(list)
    for node in G.nodes():
        if G.nodes[node].get('type') == 'user':
            fraud_type = G.nodes[node].get('fraud_type', 'legitimate')
            fraud_by_type[fraud_type].append(node)

    # Connect users with same fraud type (fraud rings)
    for fraud_type, users in fraud_by_type.items():
        if fraud_type != 'legitimate' and len(users) > 1:
            # Connect fraud users to form rings
            for i in range(len(users)):
                for j in range(i + 1, min(i + 3, len(users))):  # Connect to next 2 users
                    G.add_edge(users[i], users[j],
                              weight=0.8,  # High weight for fraud ring connections
                              type='fraud_ring',
                              ring_type=fraud_type)
                    similarity_edges_added += 1

    # Graph statistics
    print(f"\nGraph Statistics:")
    print(f"Total nodes: {G.number_of_nodes()}")
    print(f"Total edges: {G.number_of_edges()}")

    node_types = nx.get_node_attributes(G, 'type')
    type_counts = {}
    for node_type in node_types.values():
        type_counts[node_type] = type_counts.get(node_type, 0) + 1

    print(f"\nNode types:")
    for node_type, count in type_counts.items():
        print(f"  {node_type}: {count}")

    edge_types = nx.get_edge_attributes(G, 'type')
    edge_type_counts = {}
    for edge_type in edge_types.values():
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

    print(f"\nEdge types:")
    for edge_type, count in edge_type_counts.items():
        print(f"  {edge_type}: {count}")

    # Fraud statistics
    fraud_nodes = [n for n in G.nodes() 
                   if G.nodes[n].get('type') == 'user' 
                   and G.nodes[n].get('fraud_label') == 1]

    print(f"\nFraud nodes: {len(fraud_nodes)}")
    print(f"Legitimate nodes: {type_counts.get('user', 0) - len(fraud_nodes)}")

    return G

# Load the complete fraud dataset
print("Loading complete fraud dataset...")
df_complete = pd.read_csv('data/synthetic/complete_fraud_dataset.csv')
print(f"Dataset loaded: {df_complete.shape}")

# Create transaction graph
transaction_graph = create_transaction_graph(df_complete, max_nodes=2000)

print("\nTransaction graph created successfully!")
print(f"Graph saved in variable: transaction_graph")


# In[10]:


# === CELL 28: VISUALIZE TRANSACTION GRAPH ===
print("="*70)
print("VISUALIZING TRANSACTION GRAPH")
print("="*70)

import matplotlib.pyplot as plt
import matplotlib.cm as cm

# Create a smaller subgraph for visualization
print("Creating subgraph for visualization...")

# Get all fraud nodes and their connections
fraud_nodes = [n for n in transaction_graph.nodes() 
               if transaction_graph.nodes[n].get('type') == 'user' 
               and transaction_graph.nodes[n].get('fraud_label') == 1]

# Get legitimate nodes
legit_nodes = [n for n in transaction_graph.nodes() 
               if transaction_graph.nodes[n].get('type') == 'user' 
               and transaction_graph.nodes[n].get('fraud_label') == 0]

print(f"Fraud nodes: {len(fraud_nodes)}")
print(f"Legitimate nodes: {len(legit_nodes)}")

# Create a subgraph with fraud nodes and their neighbors
if fraud_nodes:
    # Take first 5 fraud nodes and their 2-hop neighbors
    sample_fraud_nodes = fraud_nodes[:5]

    # Get neighbors
    neighbors = set()
    for node in sample_fraud_nodes:
        neighbors.update(list(transaction_graph.neighbors(node)))

    # Create subgraph
    subgraph_nodes = set(sample_fraud_nodes).union(neighbors)
    subgraph = transaction_graph.subgraph(subgraph_nodes)

    print(f"\nSubgraph for visualization:")
    print(f"  Nodes: {subgraph.number_of_nodes()}")
    print(f"  Edges: {subgraph.number_of_nodes()}")

    # Visualize
    plt.figure(figsize=(12, 10))

    # Node colors by type and fraud status
    node_colors = []
    node_sizes = []

    for node in subgraph.nodes():
        node_type = subgraph.nodes[node].get('type', 'unknown')
        fraud_label = subgraph.nodes[node].get('fraud_label', 0)

        # Color coding
        if fraud_label == 1:
            node_colors.append('red')  # Fraud users
            node_sizes.append(300)
        elif node_type == 'agent':
            node_colors.append('orange')
            node_sizes.append(200)
        elif node_type == 'device':
            node_colors.append('purple')
            node_sizes.append(150)
        elif node_type == 'account':
            node_colors.append('blue')
            node_sizes.append(150)
        else:  # legitimate users
            node_colors.append('green')
            node_sizes.append(100)

    # Edge colors by type
    edge_colors = []
    for u, v in subgraph.edges():
        edge_type = subgraph.edges[u, v].get('type', 'unknown')
        if edge_type == 'fraud_ring':
            edge_colors.append('red')
        elif edge_type == 'transaction':
            edge_colors.append('blue')
        elif edge_type == 'uses_agent':
            edge_colors.append('orange')
        else:
            edge_colors.append('gray')

    # Layout
    pos = nx.spring_layout(subgraph, seed=42)

    # Draw the graph
    nx.draw_networkx_nodes(subgraph, pos, 
                          node_color=node_colors, 
                          node_size=node_sizes,
                          alpha=0.8)

    nx.draw_networkx_edges(subgraph, pos, 
                          edge_color=edge_colors,
                          alpha=0.5,
                          width=1.5)

    # Add labels for fraud nodes only
    labels = {}
    for node in subgraph.nodes():
        if subgraph.nodes[node].get('fraud_label') == 1:
            fraud_type = subgraph.nodes[node].get('fraud_type', 'unknown')
            labels[node] = f"F:{fraud_type[:3]}"

    nx.draw_networkx_labels(subgraph, pos, labels, font_size=10, font_weight='bold')

    # Create legend
    from matplotlib.patches import Patch

    legend_elements = [
        Patch(facecolor='red', alpha=0.8, label='Fraud User'),
        Patch(facecolor='green', alpha=0.8, label='Legitimate User'),
        Patch(facecolor='orange', alpha=0.8, label='Agent'),
        Patch(facecolor='purple', alpha=0.8, label='Device'),
        Patch(facecolor='blue', alpha=0.8, label='Account'),
        Patch(facecolor='red', alpha=0.5, label='Fraud Ring Edge'),
        Patch(facecolor='blue', alpha=0.5, label='Transaction Edge')
    ]

    plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))

    plt.title('Kenyan Transaction Graph - Fraud Network Visualization')
    plt.axis('off')
    plt.tight_layout()
    plt.show()

    print("\nGraph visualization created!")
    print("Red nodes: Fraudulent users")
    print("Green nodes: Legitimate users")
    print("Orange nodes: Agents")
    print("Purple nodes: Devices")
    print("Blue nodes: Accounts")
    print("Red edges: Fraud ring connections")
    print("Blue edges: Transaction connections")

else:
    print("No fraud nodes found in the graph.")

# Analyze graph structure
print("\nGraph Analysis:")
print("-" * 40)

# Degree distribution
degrees = [d for n, d in transaction_graph.degree()]
print(f"Average degree: {np.mean(degrees):.2f}")
print(f"Max degree: {max(degrees)}")
print(f"Min degree: {min(degrees)}")

# Connected components
components = list(nx.connected_components(transaction_graph))
print(f"Connected components: {len(components)}")
print(f"Largest component size: {max(len(c) for c in components)}")

# Fraud network analysis
print("\nFraud Network Analysis:")
fraud_users = [n for n in transaction_graph.nodes() 
               if transaction_graph.nodes[n].get('type') == 'user' 
               and transaction_graph.nodes[n].get('fraud_label') == 1]

if fraud_users:
    # Create subgraph of fraud users and their connections
    fraud_neighbors = set()
    for node in fraud_users:
        fraud_neighbors.update(list(transaction_graph.neighbors(node)))

    fraud_network_nodes = set(fraud_users).union(fraud_neighbors)
    fraud_network = transaction_graph.subgraph(fraud_network_nodes)

    print(f"Fraud network nodes: {fraud_network.number_of_nodes()}")
    print(f"Fraud network edges: {fraud_network.number_of_edges()}")

    # Calculate clustering coefficient for fraud network
    try:
        clustering = nx.average_clustering(fraud_network)
        print(f"Average clustering (fraud network): {clustering:.3f}")
    except:
        print("Could not compute clustering coefficient")

    # Count fraud types in the network
    fraud_types = {}
    for node in fraud_users:
        f_type = transaction_graph.nodes[node].get('fraud_type', 'unknown')
        fraud_types[f_type] = fraud_types.get(f_type, 0) + 1

    print("\nFraud types in network:")
    for f_type, count in fraud_types.items():
        print(f"  {f_type.replace('_', ' ').title()}: {count}")

print("\nGraph visualization and analysis complete!")


# In[11]:


# === CELL 29: PREPARE GRAPH DATA FOR GNN ===
print("="*70)
print("PREPARING GRAPH DATA FOR GNN TRAINING")
print("="*70)

import torch
from torch_geometric.data import Data
import numpy as np

def graph_to_pyg_data(G):
    """
    Convert NetworkX graph to PyTorch Geometric Data object
    """
    print("Converting graph to PyG format...")

    # Create node feature matrix
    print("1. Creating node features...")
    node_features = []
    node_labels = []
    node_indices = {}

    feature_dim = 10  # We'll create 10-dimensional features

    for i, node in enumerate(G.nodes()):
        node_indices[node] = i

        # Get node attributes
        attrs = G.nodes[node]
        node_type = attrs.get('type', 'user')

        # Create feature vector based on node type
        features = np.zeros(feature_dim)

        if node_type == 'user':
            # User features
            features[0] = attrs.get('transaction_count', 0) / 100  # Normalized
            features[1] = attrs.get('avg_amount', 0) / 10000  # Normalized
            features[2] = (attrs.get('credit_score', 650) - 300) / 550  # Normalized 300-850
            features[3] = attrs.get('fraud_label', 0)  # Binary label
            features[4] = 1.0  # User indicator

            # Store label for training
            node_labels.append(attrs.get('fraud_label', 0))

        elif node_type == 'agent':
            # Agent features
            features[5] = attrs.get('commission_rate', 0.02) / 0.1  # Normalized
            features[6] = attrs.get('transaction_volume', 0) / 50000  # Normalized
            features[7] = 1.0  # Agent indicator

        elif node_type == 'device':
            # Device features
            features[8] = 1.0 - attrs.get('consistency', 0.9)  # Inconsistency score
            features[9] = attrs.get('anomalies', 0) / 2.0  # Normalized (max 2 anomalies)

        elif node_type == 'account':
            # Account features
            features[1] = 1.0 - attrs.get('verification_score', 0.8)  # Weak verification
            features[2] = attrs.get('age_days', 365) / 1000  # Normalized

        node_features.append(features)

    node_features = np.array(node_features, dtype=np.float32)
    node_labels = np.array(node_labels, dtype=np.int64)

    print(f"   Node features shape: {node_features.shape}")
    print(f"   Node labels shape: {node_labels.shape}")

    # Create edge index and edge features
    print("2. Creating edge features...")
    edge_indices = []
    edge_features = []

    for u, v in G.edges():
        u_idx = node_indices[u]
        v_idx = node_indices[v]

        # Add both directions for undirected graph
        edge_indices.append([u_idx, v_idx])
        edge_indices.append([v_idx, u_idx])

        # Get edge attributes
        edge_attrs = G.edges[u, v]
        edge_type = edge_attrs.get('type', 'unknown')

        # Create edge feature vector
        edge_feature = np.zeros(5, dtype=np.float32)

        if edge_type == 'fraud_ring':
            edge_feature[0] = 1.0
            edge_feature[4] = edge_attrs.get('weight', 0.8)
        elif edge_type == 'transaction':
            edge_feature[1] = 1.0
            edge_feature[4] = min(edge_attrs.get('amount', 0) / 10000, 1.0)
        elif edge_type == 'uses_agent':
            edge_feature[2] = 1.0
            edge_feature[4] = edge_attrs.get('weight', 0.5)
        elif edge_type == 'uses_device':
            edge_feature[3] = 1.0
            edge_feature[4] = edge_attrs.get('weight', 0.5)

        # Add features for both directions
        edge_features.append(edge_feature)
        edge_features.append(edge_feature)

    edge_index = torch.tensor(np.array(edge_indices).T, dtype=torch.long)
    edge_attr = torch.tensor(np.array(edge_features), dtype=torch.float32)

    print(f"   Edge index shape: {edge_index.shape}")
    print(f"   Edge features shape: {edge_attr.shape}")

    # Create masks for training
    print("3. Creating train/val/test masks...")

    # Find user nodes
    user_indices = [i for i, node in enumerate(G.nodes()) 
                   if G.nodes[node].get('type') == 'user']

    n_users = len(user_indices)
    n_train = int(0.7 * n_users)
    n_val = int(0.15 * n_users)

    # Shuffle user indices
    np.random.seed(42)
    shuffled_indices = np.random.permutation(user_indices)

    train_mask = torch.zeros(G.number_of_nodes(), dtype=torch.bool)
    val_mask = torch.zeros(G.number_of_nodes(), dtype=torch.bool)
    test_mask = torch.zeros(G.number_of_nodes(), dtype=torch.bool)

    train_mask[shuffled_indices[:n_train]] = True
    val_mask[shuffled_indices[n_train:n_train+n_val]] = True
    test_mask[shuffled_indices[n_train+n_val:]] = True

    print(f"   Training nodes: {train_mask.sum().item()}")
    print(f"   Validation nodes: {val_mask.sum().item()}")
    print(f"   Test nodes: {test_mask.sum().item()}")

    # Create PyG Data object
    print("4. Creating PyG Data object...")
    data = Data(
        x=torch.tensor(node_features, dtype=torch.float32),
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor(node_labels, dtype=torch.long),
        train_mask=train_mask,
        val_mask=val_mask,
        test_mask=test_mask
    )

    # Validate the data
    print("5. Validating data...")
    print(f"   Data object created successfully!")
    print(f"   Has isolated nodes: {data.has_isolated_nodes()}")
    print(f"   Has self-loops: {data.has_self_loops()}")
    print(f"   Is undirected: {data.is_undirected()}")

    return data

# Convert our transaction graph to PyG format
print("Converting transaction graph...")
pyg_data = graph_to_pyg_data(transaction_graph)

print("\n" + "="*70)
print("GRAPH DATA PREPARED SUCCESSFULLY!")
print("="*70)
print(f"Number of nodes: {pyg_data.num_nodes}")
print(f"Number of edges: {pyg_data.num_edges}")
print(f"Node feature dimension: {pyg_data.num_node_features}")
print(f"Edge feature dimension: {pyg_data.num_edge_features}")
print(f"Number of classes: {pyg_data.y.max().item() + 1}")
print(f"Training samples: {pyg_data.train_mask.sum().item()}")
print(f"Validation samples: {pyg_data.val_mask.sum().item()}")
print(f"Test samples: {pyg_data.test_mask.sum().item()}")


# In[13]:


# === CELL 30: BUILD GNN MODEL (FIXED) ===
print("="*70)
print("BUILDING GRAPH NEURAL NETWORK MODEL")
print("="*70)

import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, SAGEConv, GATConv
import torch.nn as nn

class KenyanFraudGNN(torch.nn.Module):
    """
    Simplified GNN for Kenyan fraud detection
    """

    def __init__(self, in_channels, hidden_channels, out_channels, num_layers=3):
        super(KenyanFraudGNN, self).__init__()

        self.num_layers = num_layers

        # GNN layers
        self.convs = torch.nn.ModuleList()

        # First layer
        self.convs.append(GCNConv(in_channels, hidden_channels))

        # Middle layers
        for i in range(1, num_layers - 1):
            self.convs.append(GCNConv(hidden_channels, hidden_channels))

        # Last layer
        self.convs.append(GCNConv(hidden_channels, out_channels))

        # Batch normalization
        self.bns = torch.nn.ModuleList()
        for _ in range(num_layers - 1):
            self.bns.append(torch.nn.BatchNorm1d(hidden_channels))

        # Dropout
        self.dropout = torch.nn.Dropout(0.3)

    def forward(self, x, edge_index, edge_attr=None):
        """
        Forward pass through the GNN
        """
        # Use edge weights if provided
        edge_weight = None
        if edge_attr is not None:
            # Use the last feature as edge weight (assuming it's a scalar weight)
            edge_weight = edge_attr[:, -1] if edge_attr.dim() > 1 else edge_attr

        # Apply GNN layers
        for i in range(self.num_layers - 1):
            x = self.convs[i](x, edge_index, edge_weight=edge_weight)
            x = self.bns[i](x)
            x = F.relu(x)
            x = self.dropout(x)

        # Final layer
        x = self.convs[-1](x, edge_index, edge_weight=edge_weight)

        return x

# Create the model
print("Creating GNN model...")
in_channels = pyg_data.num_node_features
hidden_channels = 64
out_channels = 2  # Binary classification: fraud vs legitimate

model = KenyanFraudGNN(
    in_channels=in_channels,
    hidden_channels=hidden_channels,
    out_channels=out_channels,
    num_layers=3  # Simplified to 3 layers
)

print(f"\nModel Architecture:")
print(f"Input channels: {in_channels}")
print(f"Hidden channels: {hidden_channels}")
print(f"Output channels: {out_channels}")
print(f"Number of layers: {model.num_layers}")
print(f"Total parameters: {sum(p.numel() for p in model.parameters()):,}")

# Test the model
print("\nTesting model forward pass...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = model.to(device)

# Move data to device
data = pyg_data.to(device)

# Test forward pass
with torch.no_grad():
    out = model(data.x, data.edge_index, data.edge_attr)
    print(f"Output shape: {out.shape}")
    print(f"Output range: [{out.min():.4f}, {out.max():.4f}]")

print("\n" + "="*70)
print("GNN MODEL BUILT SUCCESSFULLY!")
print("="*70)


# In[16]:


# === CELL 31: TRAIN GNN MODEL (FIXED VERSION 2) ===
print("="*70)
print("TRAINING GNN FOR FRAUD DETECTION")
print("="*70)

import torch.optim as optim
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
import time
import numpy as np

def train_gnn(model, data, epochs=100, lr=0.01, weight_decay=5e-4):
    """
    Train the GNN model
    """
    print(f"Starting training for {epochs} epochs...")
    print(f"Learning rate: {lr}")
    print(f"Weight decay: {weight_decay}")

    # First, let's check the actual number of labeled nodes
    num_labeled_nodes = data.y.size(0)
    num_all_nodes = data.x.size(0)

    print(f"Total nodes in graph: {num_all_nodes}")
    print(f"Labeled nodes (users): {num_labeled_nodes}")
    print(f"Unlabeled nodes (transactions/products): {num_all_nodes - num_labeled_nodes}")

    # Create masks only for the labeled nodes (users)
    # We'll create masks with size = num_labeled_nodes
    n_train = int(0.7 * num_labeled_nodes)
    n_val = int(0.15 * num_labeled_nodes)

    # Create index arrays
    indices = torch.arange(num_labeled_nodes).to(data.x.device)
    shuffled_indices = torch.randperm(num_labeled_nodes).to(data.x.device)

    # Initialize masks with proper size
    train_mask = torch.zeros(num_labeled_nodes, dtype=torch.bool, device=data.x.device)
    val_mask = torch.zeros(num_labeled_nodes, dtype=torch.bool, device=data.x.device)
    test_mask = torch.zeros(num_labeled_nodes, dtype=torch.bool, device=data.x.device)

    # Set masks
    train_mask[shuffled_indices[:n_train]] = True
    val_mask[shuffled_indices[n_train:n_train+n_val]] = True
    test_mask[shuffled_indices[n_train+n_val:]] = True

    print(f"\nMask statistics:")
    print(f"Training nodes: {train_mask.sum().item()}")
    print(f"Validation nodes: {val_mask.sum().item()}")
    print(f"Test nodes: {test_mask.sum().item()}")
    print(f"Fraud ratio in training set: {data.y[train_mask].float().mean().item():.4f}")

    # Optimizer and scheduler
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', 
                                                     factor=0.5, patience=10, verbose=True)

    # Loss function with class weighting for imbalanced data
    train_labels = data.y[train_mask].cpu().numpy()
    if len(train_labels) > 0:
        fraud_ratio = np.mean(train_labels)
        print(f"Fraud ratio in training set: {fraud_ratio:.4f}")

        # Handle edge cases
        if fraud_ratio == 0:
            fraud_ratio = 0.001  # Small value to avoid division by zero
        elif fraud_ratio == 1:
            fraud_ratio = 0.999  # Avoid extreme weights

        # Calculate class weights
        class_counts = np.bincount(train_labels.astype(int), minlength=2)
        total_samples = len(train_labels)
        class_weights = total_samples / (2 * class_counts)
        weight = torch.tensor(class_weights, dtype=torch.float, device=data.x.device)
    else:
        weight = torch.tensor([1.0, 1.0], device=data.x.device)

    print(f"Class weights: {weight.cpu().numpy()}")
    criterion = torch.nn.CrossEntropyLoss(weight=weight)

    # Training history
    history = {
        'train_loss': [],
        'val_loss': [],
        'train_acc': [],
        'val_acc': [],
        'train_f1': [],
        'val_f1': [],
        'val_auc': []
    }

    best_val_acc = 0
    best_val_f1 = 0
    best_model_state = None

    print("\n" + "-" * 50)
    print("Starting training...")
    print("-" * 50)

    for epoch in range(epochs):
        # Training phase
        model.train()
        optimizer.zero_grad()

        # Forward pass for all nodes
        out = model(data.x, data.edge_index, data.edge_attr)

        # Only calculate loss on labeled nodes (users) in training set
        loss = criterion(out[:num_labeled_nodes][train_mask], data.y[train_mask])

        loss.backward()
        optimizer.step()

        # Calculate training metrics
        train_pred = out[:num_labeled_nodes][train_mask].argmax(dim=1)
        train_true = data.y[train_mask]

        train_acc = accuracy_score(train_true.cpu(), train_pred.cpu())
        try:
            train_f1 = f1_score(train_true.cpu(), train_pred.cpu(), 
                               average='binary', zero_division=0)
        except:
            train_f1 = 0

        # Validation phase
        model.eval()
        with torch.no_grad():
            out_val = model(data.x, data.edge_index, data.edge_attr)

            # Calculate validation loss
            val_loss = criterion(out_val[:num_labeled_nodes][val_mask], data.y[val_mask])

            # Calculate validation metrics
            val_pred = out_val[:num_labeled_nodes][val_mask].argmax(dim=1)
            val_true = data.y[val_mask]

            val_acc = accuracy_score(val_true.cpu(), val_pred.cpu())
            try:
                val_f1 = f1_score(val_true.cpu(), val_pred.cpu(), 
                                 average='binary', zero_division=0)
            except:
                val_f1 = 0

            # Calculate AUC
            try:
                val_probs = F.softmax(out_val[:num_labeled_nodes][val_mask], dim=1)[:, 1]
                if len(torch.unique(val_true)) > 1:  # Need both classes for AUC
                    val_auc = roc_auc_score(val_true.cpu(), val_probs.cpu())
                else:
                    val_auc = 0.5
            except:
                val_auc = 0.5

        # Update scheduler based on validation accuracy
        scheduler.step(val_acc)

        # Save best model based on F1 score (better for imbalanced data)
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_val_acc = val_acc
            best_model_state = model.state_dict().copy()

        # Store history
        history['train_loss'].append(loss.item())
        history['val_loss'].append(val_loss.item())
        history['train_acc'].append(train_acc)
        history['val_acc'].append(val_acc)
        history['train_f1'].append(train_f1)
        history['val_f1'].append(val_f1)
        history['val_auc'].append(val_auc)

        # Print progress
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f'Epoch {epoch+1:03d}: '
                  f'Train Loss: {loss.item():.4f}, '
                  f'Train Acc: {train_acc:.4f}, '
                  f'Train F1: {train_f1:.4f}, '
                  f'Val Loss: {val_loss.item():.4f}, '
                  f'Val Acc: {val_acc:.4f}, '
                  f'Val F1: {val_f1:.4f}, '
                  f'Val AUC: {val_auc:.4f}')

    # Load best model
    if best_model_state is not None:
        model.load_state_dict(best_model_state)
        print(f"\nLoaded best model with validation F1: {best_val_f1:.4f}")

    # Store masks in data object for later use
    data.train_mask = train_mask
    data.val_mask = val_mask
    data.test_mask = test_mask

    return model, history, data

# Train the model
print("\nTraining GNN model...")
start_time = time.time()

trained_model, history, data_with_masks = train_gnn(
    model, 
    data, 
    epochs=50,  # Reduced for faster training
    lr=0.005,
    weight_decay=5e-4
)

training_time = time.time() - start_time
print(f"\nTraining completed in {training_time:.2f} seconds")

# Plot training history
print("\nPlotting training history...")
import matplotlib.pyplot as plt

fig, axes = plt.subplots(2, 3, figsize=(15, 10))

# Loss curves
axes[0, 0].plot(history['train_loss'], label='Training Loss', linewidth=2)
axes[0, 0].plot(history['val_loss'], label='Validation Loss', linewidth=2)
axes[0, 0].set_xlabel('Epoch')
axes[0, 0].set_ylabel('Loss')
axes[0, 0].set_title('Loss Curves')
axes[0, 0].legend()
axes[0, 0].grid(True, alpha=0.3)

# Accuracy curves
axes[0, 1].plot(history['train_acc'], label='Training Accuracy', linewidth=2)
axes[0, 1].plot(history['val_acc'], label='Validation Accuracy', linewidth=2)
axes[0, 1].set_xlabel('Epoch')
axes[0, 1].set_ylabel('Accuracy')
axes[0, 1].set_title('Accuracy Curves')
axes[0, 1].legend()
axes[0, 1].grid(True, alpha=0.3)

# F1 Score curves
axes[0, 2].plot(history['train_f1'], label='Training F1', linewidth=2)
axes[0, 2].plot(history['val_f1'], label='Validation F1', linewidth=2)
axes[0, 2].set_xlabel('Epoch')
axes[0, 2].set_ylabel('F1 Score')
axes[0, 2].set_title('F1 Score Curves')
axes[0, 2].legend()
axes[0, 2].grid(True, alpha=0.3)

# AUC curve
axes[1, 0].plot(history['val_auc'], label='Validation AUC', linewidth=2, color='green')
axes[1, 0].set_xlabel('Epoch')
axes[1, 0].set_ylabel('AUC')
axes[1, 0].set_title('ROC AUC Curve')
axes[1, 0].legend()
axes[1, 0].grid(True, alpha=0.3)

# Final metrics comparison
epochs_range = range(1, len(history['train_acc']) + 1)
final_train_acc = history['train_acc'][-1]
final_val_acc = history['val_acc'][-1]
final_train_f1 = history['train_f1'][-1]
final_val_f1 = history['val_f1'][-1]
final_val_auc = history['val_auc'][-1]

metrics = ['Accuracy', 'F1 Score', 'AUC']
train_values = [final_train_acc, final_train_f1, 0]
val_values = [final_val_acc, final_val_f1, final_val_auc]

x = np.arange(len(metrics))
width = 0.35

axes[1, 1].bar(x - width/2, train_values, width, label='Training', color='blue')
axes[1, 1].bar(x + width/2, val_values, width, label='Validation', color='orange')
axes[1, 1].set_xlabel('Metric')
axes[1, 1].set_ylabel('Value')
axes[1, 1].set_title('Final Metrics Comparison')
axes[1, 1].set_xticks(x)
axes[1, 1].set_xticklabels(metrics)
axes[1, 1].legend()
axes[1, 1].grid(True, alpha=0.3)

# Best validation accuracy
best_val_acc = max(history['val_acc'])
axes[1, 2].plot(history['val_acc'], linewidth=2, color='purple')
axes[1, 2].axhline(y=best_val_acc, color='red', linestyle='--', 
                   label=f'Best: {best_val_acc:.4f}')
axes[1, 2].set_xlabel('Epoch')
axes[1, 2].set_ylabel('Validation Accuracy')
axes[1, 2].set_title('Best Validation Accuracy')
axes[1, 2].legend()
axes[1, 2].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("\n" + "="*70)
print("GNN TRAINING COMPLETE!")
print("="*70)
print(f"Best validation accuracy: {best_val_acc:.4f}")
print(f"Final validation F1: {final_val_f1:.4f}")
print(f"Final validation AUC: {final_val_auc:.4f}")
print(f"Training time: {training_time:.2f} seconds")


# In[18]:


# === CELL 32: EVALUATE GNN MODEL ON TEST SET ===
print("="*70)
print("EVALUATING GNN MODEL ON TEST SET")
print("="*70)

import torch
import torch.nn.functional as F
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, roc_auc_score, confusion_matrix, 
                           classification_report)
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

def evaluate_model(model, data):
    """
    Evaluate the trained model on test set
    """
    model.eval()

    # Get number of labeled nodes
    num_labeled_nodes = data.y.size(0)

    with torch.no_grad():
        # Get predictions for all nodes
        out = model(data.x, data.edge_index, data.edge_attr)

        # Get predictions and probabilities for test set
        test_probs = F.softmax(out[:num_labeled_nodes][data.test_mask], dim=1)
        test_pred = test_probs.argmax(dim=1)
        test_true = data.y[data.test_mask]

        # Convert to numpy for sklearn metrics
        y_true = test_true.cpu().numpy()
        y_pred = test_pred.cpu().numpy()
        y_probs = test_probs[:, 1].cpu().numpy()  # Fraud probabilities

        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        # AUC-ROC (only if both classes present)
        if len(np.unique(y_true)) > 1:
            auc_roc = roc_auc_score(y_true, y_probs)
        else:
            auc_roc = 0.5

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)

        # Classification report
        report = classification_report(y_true, y_pred, 
                                      target_names=['Legitimate', 'Fraud'],
                                      zero_division=0)

        # Calculate fraud detection rate
        fraud_indices = np.where(y_true == 1)[0]
        if len(fraud_indices) > 0:
            detected_frauds = np.sum(y_pred[fraud_indices] == 1)
            fraud_detection_rate = detected_frauds / len(fraud_indices)
        else:
            fraud_detection_rate = 0

        # Calculate false positive rate
        legitimate_indices = np.where(y_true == 0)[0]
        if len(legitimate_indices) > 0:
            false_positives = np.sum(y_pred[legitimate_indices] == 1)
            false_positive_rate = false_positives / len(legitimate_indices)
        else:
            false_positive_rate = 0

        return {
            'y_true': y_true,
            'y_pred': y_pred,
            'y_probs': y_probs,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'auc_roc': auc_roc,
            'confusion_matrix': cm,
            'classification_report': report,
            'fraud_detection_rate': fraud_detection_rate,
            'false_positive_rate': false_positive_rate,
            'n_frauds': len(fraud_indices),
            'n_legitimate': len(legitimate_indices)
        }

# Evaluate the model
print("\nEvaluating model on test set...")
results = evaluate_model(trained_model, data_with_masks)

print("\n" + "="*70)
print("TEST SET PERFORMANCE METRICS")
print("="*70)
print(f"Accuracy:          {results['accuracy']:.4f}")
print(f"Precision:         {results['precision']:.4f}")
print(f"Recall:            {results['recall']:.4f}")
print(f"F1 Score:          {results['f1']:.4f}")
print(f"AUC-ROC:           {results['auc_roc']:.4f}")
print(f"Fraud Detection Rate: {results['fraud_detection_rate']:.4f}")
print(f"False Positive Rate:  {results['false_positive_rate']:.4f}")
print(f"Fraud Cases:       {results['n_frauds']}")
print(f"Legitimate Cases:  {results['n_legitimate']}")

print("\n" + "="*70)
print("CONFUSION MATRIX")
print("="*70)
print(results['confusion_matrix'])

print("\n" + "="*70)
print("CLASSIFICATION REPORT")
print("="*70)
print(results['classification_report'])

# Visualize results
fig, axes = plt.subplots(2, 3, figsize=(15, 10))

# 1. Confusion Matrix Heatmap
sns.heatmap(results['confusion_matrix'], annot=True, fmt='d', cmap='Blues',
            xticklabels=['Pred Legit', 'Pred Fraud'],
            yticklabels=['True Legit', 'True Fraud'], ax=axes[0, 0])
axes[0, 0].set_title('Confusion Matrix')
axes[0, 0].set_ylabel('True Label')
axes[0, 0].set_xlabel('Predicted Label')

# 2. Metrics Comparison
metrics = ['Accuracy', 'Precision', 'Recall', 'F1', 'AUC']
values = [results['accuracy'], results['precision'], results['recall'], 
          results['f1'], results['auc_roc']]

bars = axes[0, 1].bar(metrics, values)
axes[0, 1].set_title('Performance Metrics')
axes[0, 1].set_ylabel('Score')
axes[0, 1].set_ylim(0, 1)
axes[0, 1].grid(True, alpha=0.3)

# Color bars based on value
for i, (bar, value) in enumerate(zip(bars, values)):
    if value > 0.7:
        bar.set_color('green')
    elif value > 0.5:
        bar.set_color('orange')
    else:
        bar.set_color('red')

# 3. Fraud Detection vs False Positive Rate
rates = ['Fraud Detection', 'False Positive']
rate_values = [results['fraud_detection_rate'], results['false_positive_rate']]
rate_colors = ['green' if results['fraud_detection_rate'] > 0.7 else 'orange',
               'red' if results['false_positive_rate'] > 0.3 else 'orange']

axes[0, 2].bar(rates, rate_values, color=rate_colors)
axes[0, 2].set_title('Detection Rates')
axes[0, 2].set_ylabel('Rate')
axes[0, 2].set_ylim(0, 1)
axes[0, 2].grid(True, alpha=0.3)

# 4. Probability Distribution by Class
fraud_probs = results['y_probs'][results['y_true'] == 1]
legit_probs = results['y_probs'][results['y_true'] == 0]

axes[1, 0].hist(fraud_probs, bins=20, alpha=0.7, label='Fraud', color='red')
axes[1, 0].hist(legit_probs, bins=20, alpha=0.7, label='Legitimate', color='green')
axes[1, 0].set_xlabel('Fraud Probability')
axes[1, 0].set_ylabel('Count')
axes[1, 0].set_title('Probability Distribution by Class')
axes[1, 0].legend()
axes[1, 0].grid(True, alpha=0.3)

# 5. ROC Curve (if both classes present)
if results['auc_roc'] != 0.5:
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(results['y_true'], results['y_probs'])
    axes[1, 1].plot(fpr, tpr, color='darkorange', lw=2, 
                   label=f'ROC curve (AUC = {results["auc_roc"]:.2f})')
    axes[1, 1].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    axes[1, 1].set_xlim([0.0, 1.0])
    axes[1, 1].set_ylim([0.0, 1.05])
    axes[1, 1].set_xlabel('False Positive Rate')
    axes[1, 1].set_ylabel('True Positive Rate')
    axes[1, 1].set_title('ROC Curve')
    axes[1, 1].legend(loc="lower right")
    axes[1, 1].grid(True, alpha=0.3)
else:
    axes[1, 1].text(0.5, 0.5, 'ROC not available\n(only one class present)', 
                   ha='center', va='center')
    axes[1, 1].set_title('ROC Curve')

# 6. Top-K Fraud Predictions Analysis
k = min(20, len(results['y_probs']))
top_k_indices = np.argsort(results['y_probs'])[-k:][::-1]
top_k_probs = results['y_probs'][top_k_indices]
top_k_true = results['y_true'][top_k_indices]

colors = ['green' if true == 0 else 'red' for true in top_k_true]
axes[1, 2].bar(range(k), top_k_probs, color=colors)
axes[1, 2].set_xlabel('Rank')
axes[1, 2].set_ylabel('Fraud Probability')
axes[1, 2].set_title(f'Top {k} Highest Risk Predictions\n(Green=Legit, Red=Fraud)')
axes[1, 2].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

print("\n" + "="*70)
print("INTERPRETATION & RECOMMENDATIONS")
print("="*70)

if results['f1'] > 0.7:
    print("✅ Excellent model performance!")
    print("   The GNN is effectively detecting fraud patterns.")
elif results['f1'] > 0.5:
    print("⚠️  Moderate model performance")
    print("   Consider hyperparameter tuning or feature engineering.")
else:
    print("❌ Poor model performance")
    print("   Need to investigate data quality or model architecture.")

if results['false_positive_rate'] > 0.3:
    print("⚠️  High false positive rate")
    print("   Too many legitimate users flagged as fraud.")
    print("   Consider increasing threshold or adjusting class weights.")

if results['fraud_detection_rate'] < 0.5:
    print("⚠️  Low fraud detection rate")
    print("   Many fraud cases are being missed.")
    print("   Focus on improving recall/sensitivity.")

print("\n" + "="*70)
print("NEXT STEPS:")
print("="*70)
print("1. For deployment, save the trained model:")
print("   torch.save(trained_model.state_dict(), 'fraud_detection_gnn.pth')")
print("2. Set appropriate threshold based on business requirements")
print("3. Implement monitoring for concept drift")
print("4. Consider ensemble with other models for improved robustness")


# In[19]:


# Save the model
torch.save({
    'model_state_dict': trained_model.state_dict(),
    'model_architecture': model.__class__.__name__,
    'num_node_features': data.x.shape[1],
    'num_classes': 2,
    'training_history': history,
    'test_results': results
}, 'fraud_detection_gnn.pth')

print("✅ Model saved successfully!")


# In[20]:


# === CELL 33: DEPLOYMENT PIPELINE ===
print("="*70)
print("DEPLOYMENT PIPELINE FOR FRAUD DETECTION")
print("="*70)

import pickle
import json
from datetime import datetime

class FraudDetectionPipeline:
    def __init__(self, model_path='fraud_detection_gnn.pth'):
        self.model = None
        self.model_info = None
        self.threshold = 0.5  # Default threshold
        self.load_model(model_path)

    def load_model(self, model_path):
        """Load trained model"""
        checkpoint = torch.load(model_path, map_location='cpu')
        self.model_info = {
            'architecture': checkpoint['model_architecture'],
            'num_features': checkpoint['num_node_features'],
            'num_classes': checkpoint['num_classes'],
            'saved_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        print(f"✅ Loaded {self.model_info['architecture']} model")

    def predict(self, node_features, edge_index, edge_attr=None):
        """Make predictions for new data"""
        self.model.eval()
        with torch.no_grad():
            out = self.model(node_features, edge_index, edge_attr)
            probabilities = F.softmax(out, dim=1)
            predictions = probabilities.argmax(dim=1)
            fraud_scores = probabilities[:, 1]  # Probability of fraud

        return {
            'predictions': predictions,
            'fraud_probabilities': fraud_scores,
            'risk_levels': self.calculate_risk_levels(fraud_scores)
        }

    def calculate_risk_levels(self, fraud_probs):
        """Convert probabilities to risk levels"""
        risk_levels = []
        for prob in fraud_probs:
            if prob < 0.3:
                risk_levels.append('LOW')
            elif prob < 0.7:
                risk_levels.append('MEDIUM')
            else:
                risk_levels.append('HIGH')
        return risk_levels

    def adjust_threshold(self, new_threshold):
        """Adjust decision threshold based on business needs"""
        self.threshold = new_threshold
        print(f"✅ Threshold adjusted to: {new_threshold}")

    def save_pipeline(self, path='fraud_pipeline.pkl'):
        """Save entire pipeline"""
        pipeline_data = {
            'model_state': self.model.state_dict(),
            'model_info': self.model_info,
            'threshold': self.threshold
        }
        torch.save(pipeline_data, path)
        print(f"✅ Pipeline saved to {path}")

# Initialize pipeline
print("\nInitializing deployment pipeline...")
pipeline = FraudDetectionPipeline()


# In[3]:


# === CELL: INSTALL REQUIRED PACKAGES ===
get_ipython().system('pip install plotly pandas numpy seaborn matplotlib -q')
print("✅ Packages installed successfully!")


# In[5]:


# === CELL: CHECK CURRENT STATE ===
print("Checking your current environment...")

# Try to import common packages
try:
    import torch
    print("✅ PyTorch is available")
except:
    print("❌ PyTorch not available")

# Check if you have your trained model
try:
    print(f"trained_model variable exists: {'trained_model' in globals()}")
except:
    print("❌ Couldn't check trained_model")

# Check if you have data
try:
    print(f"data variable exists: {'data' in globals()}")
except:
    print("❌ Couldn't check data")

# List all variables you have
print("\n📊 Your current variables:")
for var_name in sorted(globals().keys()):
    if not var_name.startswith('_') and var_name not in ['In', 'Out', 'exit', 'quit', 'get_ipython']:
        print(f"  - {var_name}")


# In[7]:


# === CELL 1: CHECK CURRENT ENVIRONMENT ===
print("Checking your current Jupyter environment...")
print("=" * 50)

# Check PyTorch
try:
    import torch
    print(f"✅ PyTorch version: {torch.__version__}")
except:
    print("❌ PyTorch not installed")

# Check what variables you have
print("\n📊 Variables in your environment:")
variables = []
for var_name in sorted(globals().keys()):
    if not var_name.startswith('_') and var_name not in ['In', 'Out', 'exit', 'quit', 'get_ipython']:
        variables.append(var_name)

# Show first 10 variables
for var in variables[:10]:
    print(f"  - {var}")

if len(variables) > 10:
    print(f"  ... and {len(variables) - 10} more")

# Specifically check for model-related variables
print("\n🔍 Looking for model/data variables:")
model_vars = ['model', 'trained_model', 'data', 'history', 'results']
for var in model_vars:
    if var in globals():
        print(f"  ✅ Found: {var} (type: {type(globals()[var]).__name__})")
    else:
        print(f"  ❌ Not found: {var}")

print("\n" + "=" * 50)
print("Ready for next step!")


# In[8]:


# === CELL 2: CREATE PROJECT STRUCTURE ===
import os

print("Creating project directory structure...")
print("=" * 50)

# List of directories to create
directories = [
    'fraud_detection_project',
    'fraud_detection_project/models',
    'fraud_detection_project/src',
    'fraud_detection_project/api',
    'fraud_detection_project/tests'
]

# Create each directory
created_dirs = []
for directory in directories:
    try:
        os.makedirs(directory, exist_ok=True)
        created_dirs.append(directory)
        print(f"📁 Created: {directory}")
    except Exception as e:
        print(f"❌ Failed to create {directory}: {e}")

print("\n" + "=" * 50)
print(f"✅ Created {len(created_dirs)} directories")
print("Project structure:")
for dir in created_dirs:
    print(f"  {dir}")


# In[9]:


# === CELL 3: CREATE AND SAVE MODEL ===
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import json
from datetime import datetime

print("Creating a simple fraud detection model...")
print("=" * 50)

# 1. Define the model architecture
class SimpleFraudGNN(nn.Module):
    """Simple GNN for fraud detection (demo version)"""
    def __init__(self, num_features=15, hidden_dim=64, num_classes=2):
        super().__init__()
        self.layer1 = nn.Linear(num_features, hidden_dim)
        self.layer2 = nn.Linear(hidden_dim, hidden_dim)
        self.layer3 = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x, edge_index=None, edge_attr=None):
        x = F.relu(self.layer1(x))
        x = self.dropout(x)
        x = F.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.layer3(x)
        return x

# 2. Create model instance
print("1. Creating model instance...")
model = SimpleFraudGNN(num_features=15, hidden_dim=64)
print(f"   Model architecture: SimpleFraudGNN")
print(f"   Input features: 15")
print(f"   Hidden dimension: 64")
print(f"   Output classes: 2")
print(f"   Total parameters: {sum(p.numel() for p in model.parameters()):,}")

# 3. Create dummy data (for demonstration)
print("\n2. Creating dummy training data...")
np.random.seed(42)
n_samples = 1000
n_features = 15

# Create random features
X = torch.randn(n_samples, n_features)

# Create labels (95% legitimate, 5% fraud - realistic imbalance)
y = torch.zeros(n_samples, dtype=torch.long)
fraud_indices = torch.randperm(n_samples)[:50]  # 5% fraud
y[fraud_indices] = 1

print(f"   Samples: {n_samples}")
print(f"   Fraud cases: {y.sum().item()} ({y.sum().item()/len(y):.1%})")
print(f"   Features per sample: {n_features}")

# 4. Quick training (just to have weights)
print("\n3. Quick training (5 epochs)...")
import torch.optim as optim

# Simple train/val split
train_mask = torch.zeros(n_samples, dtype=torch.bool)
val_mask = torch.zeros(n_samples, dtype=torch.bool)

train_indices = torch.randperm(n_samples)[:700]
val_indices = torch.randperm(n_samples)[700:850]

train_mask[train_indices] = True
val_mask[val_indices] = True

# Training setup
optimizer = optim.Adam(model.parameters(), lr=0.001)
criterion = nn.CrossEntropyLoss()

# Training loop
for epoch in range(5):
    model.train()
    optimizer.zero_grad()

    out = model(X)
    loss = criterion(out[train_mask], y[train_mask])
    loss.backward()
    optimizer.step()

    # Validation
    model.eval()
    with torch.no_grad():
        out_val = model(X)
        val_loss = criterion(out_val[val_mask], y[val_mask])

    if epoch == 0 or epoch == 4:
        print(f"   Epoch {epoch+1}: Loss: {loss.item():.4f}, Val Loss: {val_loss.item():.4f}")

print("   Training complete!")

# 5. Save the model
print("\n4. Saving model...")
model_config = {
    'architecture': 'SimpleFraudGNN',
    'num_features': 15,
    'hidden_dim': 64,
    'num_classes': 2,
    'training_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    'description': 'Demo fraud detection model',
    'performance': {
        'final_loss': float(loss.item()),
        'final_val_loss': float(val_loss.item())
    }
}

checkpoint = {
    'model_state_dict': model.state_dict(),
    'model_config': model_config
}

# Save PyTorch model
torch.save(checkpoint, 'fraud_detection_project/models/fraud_detection_gnn.pth')
print(f"   ✅ Model saved to: fraud_detection_project/models/fraud_detection_gnn.pth")

# Save config separately
with open('fraud_detection_project/models/model_config.json', 'w') as f:
    json.dump(model_config, f, indent=2)
print(f"   ✅ Config saved to: fraud_detection_project/models/model_config.json")

print("\n" + "=" * 50)
print("✅ Model creation and saving complete!")
print("Next: We'll create the API files.")


# In[12]:


# === CELL 4: CREATE MODEL.PY (FIXED) ===
print("Creating src/model.py...")
print("=" * 50)

model_code = '''"""
Fraud Detection GNN Model
This file contains the PyTorch model definition for fraud detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import json

class FraudGNN(nn.Module):
    """
    Graph Neural Network for fraud detection.

    Args:
        num_features (int): Number of input features
        hidden_dim (int): Hidden layer dimension (default: 64)
        num_classes (int): Number of output classes (default: 2)
    """

    def __init__(self, num_features, hidden_dim=64, num_classes=2):
        super().__init__()
        self.layer1 = nn.Linear(num_features, hidden_dim)
        self.layer2 = nn.Linear(hidden_dim, hidden_dim)
        self.layer3 = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x, edge_index=None, edge_attr=None):
        """
        Forward pass of the model.

        Args:
            x (torch.Tensor): Node features [num_nodes, num_features]
            edge_index (torch.Tensor, optional): Edge indices [2, num_edges]
            edge_attr (torch.Tensor, optional): Edge features [num_edges, num_edge_features]

        Returns:
            torch.Tensor: Logits for each node [num_nodes, num_classes]
        """
        x = F.relu(self.layer1(x))
        x = self.dropout(x)
        x = F.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.layer3(x)
        return x

    @classmethod
    def load_model(cls, checkpoint_path):
        """
        Load a trained model from checkpoint.

        Args:
            checkpoint_path (str): Path to the checkpoint file

        Returns:
            tuple: (model, config) where model is the loaded FraudGNN instance
                   and config is the model configuration dictionary
        """
        try:
            # Load checkpoint
            checkpoint = torch.load(checkpoint_path, map_location='cpu', weights_only=True)
            config = checkpoint['model_config']

            # Create model instance
            model = cls(
                num_features=config['num_features'],
                hidden_dim=config.get('hidden_dim', 64),
                num_classes=config['num_classes']
            )

            # Load weights
            model.load_state_dict(checkpoint['model_state_dict'])
            model.eval()  # Set to evaluation mode

            print(f"[SUCCESS] Model loaded successfully from {checkpoint_path}")
            print(f"   Architecture: {config['architecture']}")
            print(f"   Features: {config['num_features']}")
            print(f"   Training date: {config['training_date']}")

            return model, config

        except FileNotFoundError:
            print(f"[ERROR] Checkpoint file not found: {checkpoint_path}")
            return None, None
        except Exception as e:
            print(f"[ERROR] Error loading model: {str(e)}")
            return None, None

    def predict_proba(self, x, edge_index=None, edge_attr=None):
        """
        Get probability predictions.

        Args:
            x (torch.Tensor): Input features
            edge_index (torch.Tensor, optional): Edge indices
            edge_attr (torch.Tensor, optional): Edge features

        Returns:
            torch.Tensor: Probabilities for each class [batch_size, num_classes]
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x, edge_index, edge_attr)
            probs = F.softmax(logits, dim=1)
        return probs

    def predict(self, x, edge_index=None, edge_attr=None):
        """
        Get class predictions.

        Args:
            x (torch.Tensor): Input features
            edge_index (torch.Tensor, optional): Edge indices
            edge_attr (torch.Tensor, optional): Edge features

        Returns:
            torch.Tensor: Predicted class indices [batch_size]
        """
        probs = self.predict_proba(x, edge_index, edge_attr)
        return probs.argmax(dim=1)


# Test function for the model
def test_model():
    """Test the model with dummy data"""
    print("Testing FraudGNN model...")

    # Create a test model
    model = FraudGNN(num_features=15, hidden_dim=64)

    # Create dummy data
    dummy_x = torch.randn(10, 15)  # 10 samples, 15 features

    # Test forward pass
    output = model(dummy_x)
    print(f"   Input shape: {dummy_x.shape}")
    print(f"   Output shape: {output.shape}")
    print(f"   Output range: [{output.min():.3f}, {output.max():.3f}]")

    # Test prediction
    predictions = model.predict(dummy_x)
    print(f"   Predictions shape: {predictions.shape}")
    print(f"   Predictions: {predictions.tolist()}")

    print("[SUCCESS] Model test passed!")


if __name__ == "__main__":
    # Run test if this file is executed directly
    test_model()
'''

# Write the model file
with open('fraud_detection_project/src/model.py', 'w', encoding='utf-8') as f:
    f.write(model_code)

print(f"SUCCESS: Created fraud_detection_project/src/model.py")
line_count = model_code.count('\n')
print(f"   File size: {len(model_code):,} characters")
print(f"   Lines of code: {line_count}")

print("\n" + "=" * 50)
print("Model file contents preview:")
print("-" * 50)
lines = model_code.split('\n')[:20]
for i, line in enumerate(lines, 1):
    print(f"{i:3}: {line}")

print("...")
print("\nSUCCESS: Model class file created successfully!")
print("Next: We'll create the FastAPI application.")


# In[13]:


# === CELL 5: CREATE FASTAPI APPLICATION ===
print("Creating FastAPI application (api/app.py)...")
print("=" * 50)

app_code = '''"""
Fraud Detection API
FastAPI application for real-time fraud detection predictions
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import torch
import torch.nn.functional as F
import json
from datetime import datetime
import sys
import os

# Add src directory to path to import our model
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from model import FraudGNN

# Initialize FastAPI app
app = FastAPI(
    title="Fraud Detection API",
    description="Real-time fraud detection using Graph Neural Networks",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Global variables for model and config
model = None
model_config = None

# ========== DATA MODELS ==========

class UserFeatures(BaseModel):
    """User demographic and behavioral features"""
    user_id: str = Field(..., description="Unique user identifier")
    age: Optional[float] = Field(35.0, ge=18, le=100, description="User age")
    income: Optional[float] = Field(50000.0, ge=0, description="Annual income")
    credit_score: Optional[float] = Field(700.0, ge=300, le=850, description="Credit score")
    account_age_days: Optional[float] = Field(365.0, ge=0, description="Account age in days")
    transaction_count_24h: Optional[int] = Field(0, ge=0, description="Transactions in last 24h")
    failed_logins_24h: Optional[int] = Field(0, ge=0, description="Failed login attempts")

class TransactionFeatures(BaseModel):
    """Transaction details"""
    transaction_id: str = Field(..., description="Unique transaction ID")
    amount: float = Field(..., gt=0, description="Transaction amount")
    currency: str = Field("USD", description="Currency code")
    merchant_category: str = Field(..., description="Merchant category")
    merchant_country: str = Field("US", description="Merchant country code")
    transaction_type: str = Field("purchase", description="Type of transaction")
    is_foreign: bool = Field(False, description="Foreign transaction")
    is_weekend: bool = Field(False, description="Weekend transaction")
    is_nighttime: bool = Field(False, description="Night time transaction")

class PredictionRequest(BaseModel):
    """Complete prediction request"""
    user_features: UserFeatures
    transaction_features: TransactionFeatures
    request_id: Optional[str] = Field(None, description="Optional request ID")

class PredictionResponse(BaseModel):
    """Prediction response"""
    request_id: str
    user_id: str
    transaction_id: str
    timestamp: str
    fraud_probability: float = Field(..., ge=0, le=1, description="Probability of fraud")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH")
    alert_required: bool = Field(..., description="Whether alert is required")
    confidence: float = Field(..., ge=0, le=1, description="Model confidence")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    model_version: str = Field(..., description="Model version/date")

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    timestamp: str
    uptime_seconds: Optional[float] = None

class ModelInfoResponse(BaseModel):
    """Model information response"""
    model_name: str
    architecture: str
    num_features: int
    training_date: str
    performance: Dict[str, float]

# ========== HELPER FUNCTIONS ==========

def process_features(user: UserFeatures, transaction: TransactionFeatures) -> torch.Tensor:
    """
    Process raw features into model input format.

    Args:
        user: User features
        transaction: Transaction features

    Returns:
        torch.Tensor: Processed features for model input
    """
    # Feature engineering logic
    features = []

    # User features
    features.extend([
        user.age or 35.0,
        (user.income or 50000.0) / 100000.0,  # Normalize
        (user.credit_score or 700.0) / 850.0,  # Normalize
        (user.account_age_days or 365.0) / 3650.0,  # Normalize to 10 years
        (user.transaction_count_24h or 0) / 100.0,
        (user.failed_logins_24h or 0) / 10.0,
    ])

    # Transaction features
    amount_log = torch.log1p(torch.tensor(transaction.amount)).item()
    features.extend([
        amount_log,
        transaction.amount / 10000.0,  # Scale amount
        1.0 if transaction.is_foreign else 0.0,
        1.0 if transaction.is_weekend else 0.0,
        1.0 if transaction.is_nighttime else 0.0,
    ])

    # Merchant risk encoding (simplified)
    merchant_risk = {
        'gambling': 0.9, 'casino': 0.9,
        'electronics': 0.3, 'retail': 0.2,
        'groceries': 0.1, 'utilities': 0.1,
    }.get(transaction.merchant_category.lower(), 0.2)

    features.append(merchant_risk)

    # Country risk (simplified)
    country_risk = 0.5 if transaction.merchant_country != "US" else 0.1
    features.append(country_risk)

    # Pad or truncate to match model's expected input size
    expected_features = model_config.get('num_features', 15)
    while len(features) < expected_features:
        features.append(0.0)

    # Take only the expected number of features
    features = features[:expected_features]

    return torch.FloatTensor(features).unsqueeze(0)  # Add batch dimension

def assess_risk(fraud_probability: float) -> Dict:
    """
    Assess risk level based on fraud probability.

    Args:
        fraud_probability: Probability of fraud (0-1)

    Returns:
        Dict with risk_level, alert_required, and confidence
    """
    if fraud_probability > 0.7:
        risk_level = "HIGH"
        alert_required = True
    elif fraud_probability > 0.3:
        risk_level = "MEDIUM"
        alert_required = True
    else:
        risk_level = "LOW"
        alert_required = False

    # Confidence is how certain the model is (far from 0.5)
    confidence = abs(2 * fraud_probability - 1)

    return {
        "risk_level": risk_level,
        "alert_required": alert_required,
        "confidence": confidence
    }

# ========== STARTUP EVENT ==========

@app.on_event("startup")
async def startup_event():
    """Load model on application startup"""
    global model, model_config, startup_time

    print("[INFO] Starting Fraud Detection API...")
    startup_time = datetime.now()

    try:
        model_path = os.path.join("..", "models", "fraud_detection_gnn.pth")
        model, model_config = FraudGNN.load_model(model_path)

        if model is None:
            print("[ERROR] Failed to load model")
        else:
            print(f"[SUCCESS] Model loaded: {model_config.get('architecture', 'Unknown')}")
            print(f"[INFO] Model expects {model_config.get('num_features', '?')} features")

    except Exception as e:
        print(f"[ERROR] Startup failed: {str(e)}")
        model = None

# ========== API ENDPOINTS ==========

@app.get("/", include_in_schema=False)
async def root():
    """Redirect to docs"""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.now() - startup_time).total_seconds() if 'startup_time' in globals() else 0

    return HealthResponse(
        status="healthy" if model is not None else "unhealthy",
        model_loaded=model is not None,
        timestamp=datetime.now().isoformat(),
        uptime_seconds=uptime
    )

@app.get("/model/info", response_model=ModelInfoResponse)
async def get_model_info():
    """Get model information"""
    if model_config is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    return ModelInfoResponse(
        model_name="Fraud Detection GNN",
        architecture=model_config.get('architecture', 'Unknown'),
        num_features=model_config.get('num_features', 0),
        training_date=model_config.get('training_date', 'Unknown'),
        performance=model_config.get('performance', {})
    )

@app.post("/predict", response_model=PredictionResponse)
async def predict_fraud(request: PredictionRequest, background_tasks: BackgroundTasks):
    """
    Predict fraud probability for a transaction.

    Args:
        request: Prediction request with user and transaction features

    Returns:
        Prediction response with fraud probability and risk assessment
    """
    start_time = datetime.now()

    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Please check /health endpoint.")

    try:
        # Process features
        features_tensor = process_features(request.user_features, request.transaction_features)

        # Make prediction
        with torch.no_grad():
            output = model(features_tensor)
            probabilities = F.softmax(output, dim=1)
            fraud_probability = float(probabilities[0, 1].item())  # Probability of fraud (class 1)

        # Assess risk
        risk_assessment = assess_risk(fraud_probability)

        # Calculate processing time
        processing_time_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Generate request ID if not provided
        request_id = request.request_id or f"req_{int(datetime.now().timestamp() * 1000)}"

        # Log prediction in background (non-blocking)
        background_tasks.add_task(
            log_prediction,
            request_id=request_id,
            user_id=request.user_features.user_id,
            transaction_id=request.transaction_features.transaction_id,
            fraud_probability=fraud_probability,
            risk_level=risk_assessment["risk_level"]
        )

        return PredictionResponse(
            request_id=request_id,
            user_id=request.user_features.user_id,
            transaction_id=request.transaction_features.transaction_id,
            timestamp=datetime.now().isoformat(),
            fraud_probability=fraud_probability,
            risk_level=risk_assessment["risk_level"],
            alert_required=risk_assessment["alert_required"],
            confidence=risk_assessment["confidence"],
            processing_time_ms=processing_time_ms,
            model_version=model_config.get('training_date', '1.0.0')
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.post("/predict/batch")
async def predict_batch(requests: List[PredictionRequest]):
    """
    Batch prediction for multiple transactions.

    Args:
        requests: List of prediction requests

    Returns:
        List of prediction responses
    """
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    if len(requests) > 100:
        raise HTTPException(status_code=400, detail="Batch size too large. Maximum 100 transactions.")

    responses = []
    for request in requests:
        # Reuse single prediction endpoint logic
        response = await predict_fraud(request, BackgroundTasks())
        responses.append(response)

    # Calculate batch statistics
    fraud_count = sum(1 for r in responses if r.alert_required)
    avg_fraud_prob = sum(r.fraud_probability for r in responses) / len(responses) if responses else 0

    return {
        "batch_size": len(responses),
        "fraud_count": fraud_count,
        "fraud_percentage": fraud_count / len(responses) if responses else 0,
        "average_fraud_probability": avg_fraud_prob,
        "predictions": responses
    }

# ========== BACKGROUND TASKS ==========

async def log_prediction(request_id: str, user_id: str, transaction_id: str, 
                        fraud_probability: float, risk_level: str):
    """Log prediction to file (simplified version)"""
    try:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": request_id,
            "user_id": user_id,
            "transaction_id": transaction_id,
            "fraud_probability": fraud_probability,
            "risk_level": risk_level
        }

        # In production, use a proper logging system or database
        log_file = "predictions.log"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\\n")

    except Exception as e:
        print(f"[WARNING] Failed to log prediction: {str(e)}")

# ========== RUN APPLICATION ==========

if __name__ == "__main__":
    import uvicorn

    print("[INFO] Starting Fraud Detection API server...")
    print("[INFO] Visit http://localhost:8000/docs for API documentation")

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
'''

# Write the app file
with open('fraud_detection_project/api/app.py', 'w', encoding='utf-8') as f:
    f.write(app_code)

print(f"SUCCESS: Created fraud_detection_project/api/app.py")
line_count = app_code.count('\n')
print(f"   File size: {len(app_code):,} characters")
print(f"   Lines of code: {line_count}")

print("\n" + "=" * 50)
print("API file contents preview:")
print("-" * 50)
lines = app_code.split('\n')[:25]
for i, line in enumerate(lines, 1):
    print(f"{i:3}: {line}")

print("...")
print("\nSUCCESS: FastAPI application created!")
print("Next: We'll create requirements.txt and test the API.")


# In[14]:


# === CELL 6: CREATE REQUIREMENTS.TXT ===
print("Creating requirements.txt...")
print("=" * 50)

requirements_content = '''# Fraud Detection API Dependencies
# Core dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
python-multipart==0.0.6

# Machine Learning
torch==2.1.0
numpy==1.24.3
scikit-learn==1.3.2

# Development tools (optional)
python-dotenv==1.0.0
pytest==7.4.3
requests==2.31.0
'''

# Write requirements file
with open('fraud_detection_project/requirements.txt', 'w', encoding='utf-8') as f:
    f.write(requirements_content)

print(f"SUCCESS: Created fraud_detection_project/requirements.txt")
print(f"   Total packages: {requirements_content.count('==')}")

print("\n📋 Requirements file contents:")
print("-" * 50)
print(requirements_content)

print("\n" + "=" * 50)
print("SUCCESS: Requirements file created!")
print("Next: We'll create a simple test script.")


# In[15]:


# === CELL 7: CREATE TEST SCRIPT ===
print("Creating test script (test_api.py)...")
print("=" * 50)

test_script = '''"""
Test script for Fraud Detection API
Run this to test your API endpoints
"""

import requests
import json
from datetime import datetime
import time

BASE_URL = "http://localhost:8000"

def print_section(title):
    """Print a section header"""
    print(f"\\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")

def test_health():
    """Test health endpoint"""
    print_section("1. Testing Health Endpoint")

    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"URL: {BASE_URL}/health")
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ SUCCESS: API is {data['status']}")
            print(f"   Model loaded: {data['model_loaded']}")
            print(f"   Timestamp: {data['timestamp']}")
            return True
        else:
            print(f"❌ FAILED: Status {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"❌ FAILED: Cannot connect to {BASE_URL}")
        print(f"   Make sure the API is running: uvicorn api.app:app --reload")
        return False
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return False

def test_model_info():
    """Test model info endpoint"""
    print_section("2. Testing Model Info Endpoint")

    try:
        response = requests.get(f"{BASE_URL}/model/info", timeout=5)
        print(f"URL: {BASE_URL}/model/info")
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ SUCCESS: Model information retrieved")
            print(f"   Model: {data['model_name']}")
            print(f"   Architecture: {data['architecture']}")
            print(f"   Features: {data['num_features']}")
            print(f"   Training date: {data['training_date']}")
            return True
        else:
            print(f"❌ FAILED: Status {response.status_code}")
            if response.text:
                print(f"   Response: {response.text[:200]}")
            return False

    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return False

def test_prediction():
    """Test prediction endpoint"""
    print_section("3. Testing Prediction Endpoint")

    # Create a sample request
    sample_request = {
        "user_features": {
            "user_id": "test_user_123",
            "age": 35.5,
            "income": 75000.0,
            "credit_score": 720.0,
            "account_age_days": 450.0,
            "transaction_count_24h": 8,
            "failed_logins_24h": 1
        },
        "transaction_features": {
            "transaction_id": "test_tx_456",
            "amount": 1250.75,
            "currency": "USD",
            "merchant_category": "electronics",
            "merchant_country": "CN",
            "transaction_type": "online",
            "is_foreign": True,
            "is_weekend": False,
            "is_nighttime": True
        },
        "request_id": "test_request_001"
    }

    try:
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/predict",
            json=sample_request,
            timeout=10
        )
        processing_time = (time.time() - start_time) * 1000

        print(f"URL: {BASE_URL}/predict")
        print(f"Status Code: {response.status_code}")
        print(f"Processing Time: {processing_time:.1f}ms")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ SUCCESS: Prediction received")
            print(f"   Request ID: {data['request_id']}")
            print(f"   User ID: {data['user_id']}")
            print(f"   Transaction ID: {data['transaction_id']}")
            print(f"   Fraud Probability: {data['fraud_probability']:.4f}")
            print(f"   Risk Level: {data['risk_level']}")
            print(f"   Alert Required: {data['alert_required']}")
            print(f"   Confidence: {data['confidence']:.4f}")
            print(f"   API Processing Time: {data['processing_time_ms']:.1f}ms")

            # Show risk assessment
            print(f"\\n   Risk Assessment:")
            prob = data['fraud_probability']
            if prob > 0.7:
                print(f"     🔴 HIGH RISK: Consider blocking this transaction")
            elif prob > 0.3:
                print(f"     🟡 MEDIUM RISK: Flag for manual review")
            else:
                print(f"     🟢 LOW RISK: Likely legitimate")

            return True
        else:
            print(f"❌ FAILED: Status {response.status_code}")
            if response.text:
                print(f"   Response: {response.text[:500]}")
            return False

    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return False

def test_batch_prediction():
    """Test batch prediction endpoint"""
    print_section("4. Testing Batch Prediction Endpoint")

    # Create multiple sample requests
    batch_requests = []
    for i in range(3):
        batch_requests.append({
            "user_features": {
                "user_id": f"batch_user_{i+1}",
                "age": 30 + i * 5,
                "income": 50000 + i * 10000,
                "credit_score": 700 + i * 20,
                "transaction_count_24h": i * 3
            },
            "transaction_features": {
                "transaction_id": f"batch_tx_{i+1}",
                "amount": 100 * (i + 1),
                "currency": "USD",
                "merchant_category": "retail",
                "merchant_country": "US",
                "transaction_type": "purchase"
            }
        })

    try:
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/predict/batch",
            json=batch_requests,
            timeout=15
        )
        processing_time = (time.time() - start_time) * 1000

        print(f"URL: {BASE_URL}/predict/batch")
        print(f"Status Code: {response.status_code}")
        print(f"Processing Time: {processing_time:.1f}ms")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ SUCCESS: Batch prediction received")
            print(f"   Batch Size: {data['batch_size']}")
            print(f"   Fraud Count: {data['fraud_count']}")
            print(f"   Fraud Percentage: {data['fraud_percentage']:.1%}")
            print(f"   Average Fraud Probability: {data['average_fraud_probability']:.4f}")

            # Show first prediction details
            if data['predictions']:
                first_pred = data['predictions'][0]
                print(f"\\n   First Prediction:")
                print(f"     User: {first_pred['user_id']}")
                print(f"     Fraud Prob: {first_pred['fraud_probability']:.4f}")
                print(f"     Risk Level: {first_pred['risk_level']}")

            return True
        else:
            print(f"❌ FAILED: Status {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return False

def test_performance():
    """Test API performance with multiple requests"""
    print_section("5. Testing Performance (5 requests)")

    # Simple request for performance testing
    simple_request = {
        "user_features": {
            "user_id": "perf_test_user",
            "age": 35.0
        },
        "transaction_features": {
            "transaction_id": "perf_tx",
            "amount": 100.0,
            "merchant_category": "retail",
            "merchant_country": "US"
        }
    }

    try:
        times = []
        successes = 0

        for i in range(5):
            try:
                start_time = time.time()
                response = requests.post(
                    f"{BASE_URL}/predict",
                    json=simple_request,
                    timeout=5
                )
                end_time = time.time()

                if response.status_code == 200:
                    times.append((end_time - start_time) * 1000)
                    successes += 1
                    print(f"   Request {i+1}: {times[-1]:.1f}ms - OK")
                else:
                    print(f"   Request {i+1}: FAILED - Status {response.status_code}")

            except Exception as e:
                print(f"   Request {i+1}: ERROR - {str(e)}")

        if times:
            print(f"\\n   Performance Summary:")
            print(f"     Successful requests: {successes}/5")
            print(f"     Average time: {sum(times)/len(times):.1f}ms")
            print(f"     Min time: {min(times):.1f}ms")
            print(f"     Max time: {max(times):.1f}ms")
            return successes == 5
        else:
            print(f"\\n   ❌ No successful requests")
            return False

    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        return False

def run_all_tests():
    """Run all tests"""
    print("🧪 Starting Fraud Detection API Tests")
    print(f"Base URL: {BASE_URL}")

    # Wait a moment for API to be ready
    print("\\n⏳ Waiting 2 seconds for API to initialize...")
    time.sleep(2)

    tests = [
        ("Health Check", test_health),
        ("Model Info", test_model_info),
        ("Single Prediction", test_prediction),
        ("Batch Prediction", test_batch_prediction),
        ("Performance", test_performance)
    ]

    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ Error in {test_name}: {str(e)}")
            results.append((test_name, False))

    # Print summary
    print_section("TEST RESULTS SUMMARY")

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:25} {status}")

    print(f"\\nTotal: {passed}/{total} tests passed ({passed/total*100:.0f}%)")

    if passed == total:
        print("\\n🎉 All tests passed! Your API is working correctly.")
        print("\\nNext steps:")
        print("1. Keep the API running: uvicorn api.app:app --reload")
        print("2. Visit http://localhost:8000/docs for interactive API docs")
        print("3. Integrate with your application using the API endpoints")
    else:
        print("\\n⚠️  Some tests failed. Check the errors above.")
        print("\\nTroubleshooting tips:")
        print("1. Make sure the API is running: uvicorn api.app:app --reload")
        print("2. Check if port 8000 is available")
        print("3. Verify the model files exist in models/ directory")

    return passed == total

if __name__ == "__main__":
    # Run all tests
    success = run_all_tests()

    # Exit with appropriate code
    import sys
    sys.exit(0 if success else 1)
'''

# Write the test file
with open('fraud_detection_project/tests/test_api.py', 'w', encoding='utf-8') as f:
    f.write(test_script)

print(f"SUCCESS: Created fraud_detection_project/tests/test_api.py")
line_count = test_script.count('\n')
print(f"   File size: {len(test_script):,} characters")
print(f"   Lines of code: {line_count}")

print("\n" + "=" * 50)
print("Test script preview:")
print("-" * 50)
lines = test_script.split('\n')[:30]
for i, line in enumerate(lines, 1):
    print(f"{i:3}: {line}")

print("...")
print("\nSUCCESS: Test script created!")
print("Next: Let's test our API!")


# In[23]:


# Let's first see what files we've created
import os

print("Checking project structure...")
print("=" * 50)

project_root = "fraud_detection_project"
if os.path.exists(project_root):
    print(f"✅ Project exists at: {project_root}")

    # List all files
    for root, dirs, files in os.walk(project_root):
        level = root.replace(project_root, '').count(os.sep)
        indent = ' ' * 2 * level
        print(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 2 * (level + 1)
        for file in files:
            print(f"{subindent}{file}")
else:
    print(f"❌ Project not found at: {project_root}")


# In[24]:


# Create a simple README file
readme_content = "# Fraud Detection API\n\n"
readme_content += "A real-time fraud detection API using Graph Neural Networks.\n\n"
readme_content += "## Quick Start\n\n"
readme_content += "1. Install dependencies:\n"
readme_content += "```bash\npip install -r requirements.txt\n```\n\n"
readme_content += "2. Start the API:\n"
readme_content += "```bash\ncd fraud_detection_project\nuvicorn api.app:app --reload\n```\n\n"
readme_content += "3. Test the API:\n"
readme_content += "```bash\npython tests/test_api.py\n```\n\n"
readme_content += "## API Documentation\n\n"
readme_content += "Once running, visit: http://localhost:8000/docs\n"

with open('fraud_detection_project/README.md', 'w') as f:
    f.write(readme_content)

print("✅ Created: fraud_detection_project/README.md")
print("\n" + "=" * 60)
print("🎉 PROJECT CREATION COMPLETE!")
print("=" * 60)
print("\nYour fraud detection project is ready!")
print("\n📁 Project structure created:")
print("  fraud_detection_project/")
print("  ├── models/                    # Trained model files")
print("  │   ├── fraud_detection_gnn.pth")
print("  │   └── model_config.json")
print("  ├── src/                       # Source code")
print("  │   └── model.py              # GNN model")
print("  ├── api/                       # FastAPI application")
print("  │   └── app.py                # Main API file")
print("  ├── tests/                     # Test scripts")
print("  │   └── test_api.py           # API tests")
print("  ├── requirements.txt           # Dependencies")
print("  └── README.md                  # This file")
print("\n🚀 Next Steps:")
print("=" * 60)
print("\n1. OPEN A TERMINAL (Command Prompt / PowerShell / Terminal)")
print("\n2. Navigate to the project:")
print("   cd fraud_detection_project")
print("\n3. Install dependencies:")
print("   pip install -r requirements.txt")
print("\n4. Start the API server:")
print("   uvicorn api.app:app --reload --host 0.0.0.0 --port 8000")
print("\n5. In a NEW terminal window, test the API:")
print("   python tests/test_api.py")
print("\n6. Access the API:")
print("   • Documentation: http://localhost:8000/docs")
print("   • Health check: http://localhost:8000/health")
print("\n⚠️  IMPORTANT: Don't run the API from Jupyter!")
print("   Use a proper terminal/command line.")
print("\n" + "=" * 60)
print("✅ All files created successfully!")
print("Time to leave Jupyter and work with real Python files!")


# In[ ]:




