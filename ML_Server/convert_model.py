import joblib
import pickle
from pathlib import Path
import os

def convert_joblib_to_pkl(joblib_path):
    """Convert a joblib model to pkl format."""
    try:
        # Convert to Path object
        joblib_path = Path(joblib_path)
        
        # Check if file exists
        if not joblib_path.exists():
            print(f"Error: File {joblib_path} does not exist!")
            return False
            
        # Load the model from joblib
        print(f"Loading model from {joblib_path}...")
        model = joblib.load(joblib_path)
        
        # Create output path (replace .joblib with .pkl)
        output_path = joblib_path.with_suffix('.pkl')
        
        # Save the model in pkl format
        print(f"Saving model to {output_path}...")
        with open(output_path, 'wb') as f:
            pickle.dump(model, f)
            
        print(f"Successfully converted model to {output_path}")
        return True
        
    except Exception as e:
        print(f"Error during conversion: {str(e)}")
        return False

if __name__ == "__main__":
    # Convert Random Forest model
    model_path = "models/random_forest.joblib"
    convert_joblib_to_pkl(model_path) 