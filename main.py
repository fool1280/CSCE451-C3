import sys
from joblib import load
import numpy as np
from parsing import disassemble_and_process
from stats import most_similar_top_5

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

    file_content = file_content.split()
    file_content = [x[:-1] for x in file_content if x[-1] == 'q']
    new_row = dict()
    cols = {
        'mov', 'push', 'call', 'lea', 'add', 'jae', 'inc', 'cmp', 'sub', 'jmp',
        'dec', 'shl', 'pop', 'xchg', 'je', 'jne', 'xor', 'test', 'ret', 'jo',
        'imul', 'and', 'in', 'jge', 'outsb', 'fstp', 'sbb', 'adc', 'jp', 'insb', 'other'
    }
    for col in cols:
        new_row[col] = 0

    for opcode in file_content:
        if opcode in cols:
            new_row[opcode] += 1
        else:
            new_row['other'] += 1
    most_similar_top_5(new_row, prediction[0])

