# CSCE451-C3

You can download an example dataset for the `MalwareAnalysis` project from the following link:

[Download Example Dataset](https://drive.google.com/file/d/1--hwCz_JKIm1IQfF19zqdLO_mTTjpGYz/view?usp=sharing)

This dataset can be used to test and train the model.

## Training the Model on Your Own Dataset

1. **Create Folder Structure**:
   From the root directory, create a folder named `MalwareAnalysis`. Inside it, create two subfolders: 
   - `Malware` for storing malware opcodes.
   - `Benign` for storing benign opcodes.

2. **Create and Activate Virtual Environment**:
   - Create a virtual environment: `python -m venv venv`
   - Activate the virtual environment:
     - Windows: `.\venv\Scripts\activate`
     - macOS/Linux: `source venv/bin/activate`

3. **Install Python Packages**:
   - Run: `pip install -r requirements.txt`

4. **Train the Model**:
   - Run: `python train.py`
   - The vectorizer to transform user input is stored in `count_vectorizer.joblib`.
   - The model is stored in `rf_opcodes_freq_ngram_2.joblib`.

## Using the Trained Model

1. **Set Up Environment** (If not already done):
   - Create and activate the virtual environment.
   - Install Python packages: `pip install -r requirements.txt`

2. **Run the Model**:
   - Execute the script with an executable filename as an argument: `python main.py <exe filename>`
