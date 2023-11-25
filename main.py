import sys
from joblib import load
# Import the function from parsing.py
from parsing import disassemble_and_process

if __name__ == "__main__":
    # Check if an argument is provided
    if len(sys.argv) != 2:
        print("Usage: python main.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    
    # Call the function from parsing.py
    disassemble_and_process(filename)

    # Load the trained model
    model = load('rf_opcodes_freq_ngram_2.joblib')
    cv2 = load('count_vectorizer.joblib')

    with open('ml_input.txt', 'r') as file:
        file_content = file.read()

    file_content_transformed = cv2.transform([file_content]).toarray()
    # Normalize the transformed data
    file_content_normalized = (file_content_transformed / file_content_transformed.sum(axis=1)[:, None]) * 100

    # Predict with the model
    prediction = model.predict(file_content_normalized)
    print("Prediction:", prediction)

