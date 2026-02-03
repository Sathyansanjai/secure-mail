import requests
import pandas as pd
import io
import os

def download_enron_dataset():
    url = "https://raw.githubusercontent.com/bdanalytics/Enron-Spam/master/data/emails.csv"
    print(f"Downloading dataset from {url}...")
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Load into pandas
        print("Parsing CSV data...")
        # The file from that repo seems to have 'text' and 'spam' columns
        # Based on typical Enron CSVs, we might need to adjust column names
        df = pd.read_csv(io.StringIO(response.text))
        
        # Standardize columns for our train_model.py
        # Current train_model.py expects 'text' and 'label'
        if 'spam' in df.columns and 'text' in df.columns:
            df = df.rename(columns={'spam': 'label'})
        elif 'label' in df.columns and 'text' in df.columns:
            pass # Already correct
        else:
            print(f"Warning: Unexpected columns {df.columns}. Attempting to guess...")
            # If columns are different, we might need more logic here
        
        # Save to local CSV
        output_file = "enron_spam.csv"
        df.to_csv(output_file, index=False)
        print(f"Successfully saved {len(df)} emails to {output_file}")
        return output_file
        
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        return None

if __name__ == "__main__":
    download_enron_dataset()
