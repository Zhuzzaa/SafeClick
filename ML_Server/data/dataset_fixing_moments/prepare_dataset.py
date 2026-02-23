import pandas as pd
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def read_urls(file_path):
    """Read URLs from a text file."""
    logger.info(f"Reading URLs from {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls

def create_full_dataset():
    """Create a combined dataset from benign and malicious URLs."""
    base_path = os.path.join('data', 'Phishing Website Detection Dataset', 'Data')
    files = [
        ('Train/benign_Train.txt', 0),
        ('Train/malign_Train.txt', 1),
        ('Test/benign_Test.txt', 0),
        ('Test/malign_Test.txt', 1),
    ]
    all_data = []
    for rel_path, label in files:
        abs_path = os.path.join(base_path, rel_path)
        urls = read_urls(abs_path)
        logger.info(f"{rel_path}: {len(urls)} urls, label={label}")
        all_data.append(pd.DataFrame({'url': urls, 'class': label}))
    df = pd.concat(all_data, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    logger.info(f"Total samples: {len(df)}")
    logger.info(f"Class distribution: {df['class'].value_counts().to_dict()}")
    output_path = os.path.join('data', 'malicious_phish.csv')
    df.to_csv(output_path, index=False)
    logger.info(f"Saved to {output_path}")

if __name__ == "__main__":
    create_full_dataset() 