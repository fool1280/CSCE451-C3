import sys
from joblib import load
import numpy as np
from parsing import disassemble_and_process
from stats import most_similar_top_5
import requests
import time
import threading

def getInfo(file):
    url = 'https://www.virustotal.com/api/v3/files/upload_url'
    headers = {
        'accept': 'application/json',
        'x-apikey': 'bd162e9eb911d1ad4c964ccc45af431dfdaa24e96f6aba72245d808bb69e1298'
    }
    response = requests.get(url, headers=headers)
    upload_url = response.json()['data']

    files = { 'file': (file, open(file, 'rb'), 'application/octet-stream') }
    headers = {
        'accept': 'application/json',
        'x-apikey': 'bd162e9eb911d1ad4c964ccc45af431dfdaa24e96f6aba72245d808bb69e1298'
    }
    response = requests.post(upload_url, files=files, headers=headers)
    analysis_url = response.json()['data']['links']['self']

    headers = {
        'accept': 'application/json',
        'x-apikey': 'bd162e9eb911d1ad4c964ccc45af431dfdaa24e96f6aba72245d808bb69e1298'
    }

    response = requests.get(analysis_url, headers=headers)
    status = response.json()['data']['attributes']['status']
    while status != 'completed':
        time.sleep(90)
        response = requests.get(analysis_url, headers=headers)
        status = response.json()['data']['attributes']['status']
    results = response.json()['data']['attributes']['results']

    harmless = set()
    malicious = set()
    suspicious = set() 
    undetected = set()
    for engine in results:
        if results[engine]['category'] == 'harmless':
            harmless.add(engine)
        elif results[engine]['category'] == 'malicious':
            malicious.add(engine)
        elif results[engine]['category'] == 'suspicious':
            suspicious.add(engine)
        elif results[engine]['category'] == 'undetected':
            undetected.add(engine)

    with open('av_report.txt', 'w') as file:
        file.write("Harmless - AV thinks the file is not malicious ({}):\n".format(len(harmless)))
        for engine in harmless:
            file.write("    " + engine + '\n')

        file.write("\nMalicious - AV thinks the file is malicious ({}):\n".format(len(malicious)))
        for engine in malicious:
            file.write("    " + engine + '\n')

        file.write("\nSuspicious - AV thinks the file is suspicious ({}):\n".format(len(suspicious)))
        for engine in suspicious:
            file.write("    " + engine + '\n')

        file.write("\nUndetected - AV has no opinion about this file ({}):\n".format(len(undetected)))
        for engine in undetected:
            file.write("    " + engine + '\n')

    print("Anti-virus scan result output to av_report.txt")


if __name__ == '__main__':
    # Check if an argument is provided
    if len(sys.argv) != 2:
        print('Usage: python main.py <filename>')
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
    info_thread = threading.Thread(target=getInfo, args=(filename,))
    info_thread.start()
    print("Waiting to get anti-vurus scan result...")

    # Now call most_similar_top_5 in the main thread
    most_similar_top_5(new_row, prediction[0])

    # After most_similar_top_5 has completed, wait for getInfo to complete
    info_thread.join()
    

