import os
import sys
from tqdm import tqdm
from argparse import ArgumentParser
import shutil
from joblib import load
import numpy as np
from parsing import disassemble_and_process
from stats import get_most_similar_top_5

def classify(model, vectorizer, filepath : str, threshold : float, criteria : str):
    ''' Classify file as benign, inconclusive, or malware. 
    Copies file and statistical info to corresponding directory.
    
    FIXME -- Currently, only malware may be classified as inconclusive    
    '''

    disassemble_and_process(filepath, cache_dir = CACHE_DIR)

    with open(f'{CACHE_DIR}/ml_input.txt', 'r') as file:
        file_content = file.read()
    
    file_content_transformed = vectorizer.transform([file_content]).toarray()
    # Normalize the transformed data
    file_content_normalized = (file_content_transformed / file_content_transformed.sum(axis=1)[:, None]) * 100

    # Predict with the model
    prediction = model.predict(file_content_normalized)
    
    
    if prediction[0] == 0:
        outpath = os.path.join(OUTPUT_BENIGN_DIR, os.path.basename(filepath))
        shutil.copy(filepath, outpath)

    else:
        # stats calculations
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

        hel, emd = get_most_similar_top_5(new_row, prediction[0],)

        hel_sim = np.mean(hel['Hellinger Distance'])
        emd_sim = np.mean(emd['EMD'])

        if criteria == 'Hellinger':
            sim = hel_sim
            sim_df = hel
        else:
            sim = emd_sim
            sim_df = emd
        
        if sim < threshold:
            outpath = os.path.join(OUTPUT_INCONCLUSIVE_DIR, os.path.basename(filepath))
        else:
            outpath = os.path.join(OUTPUT_MALWARE_DIR, os.path.basename(filepath))
        shutil.copy(filepath, outpath)

        infopath = f'{outpath}_nearest_{criteria}.csv'
        sim_df.to_csv(infopath)




if __name__ == '__main__':
    # Check if an argument is provided
    parser = ArgumentParser()
    parser.add_argument('--threshold', 
                        dest='threshold', 
                        required=False, 
                        default=0.5, 
                        type=float,
                        help = 'Given that the ML model classifies the executable as malware, this threshold determines whether executable is sent to inconclusive directory or malware directory')
    parser.add_argument('--criteria', 
                        dest='criteria', 
                        required=False, 
                        default='Hellinger', 
                        help = 'Hellinger or EMD, the statistical similarity criteria',)
    args = parser.parse_args()
    assert(0 <= args.threshold <= 1.0)
    assert(args.criteria in ['Hellinger', 'EMD'])

    INPUT_DIR = 'input'
    CACHE_DIR = 'output/cache'
    OUTPUT_MALWARE_DIR = 'output/malware'
    OUTPUT_BENIGN_DIR = 'output/benign'
    OUTPUT_INCONCLUSIVE_DIR = 'output/inconclusive'

    for dir_ in [INPUT_DIR, CACHE_DIR, OUTPUT_MALWARE_DIR, OUTPUT_BENIGN_DIR, OUTPUT_INCONCLUSIVE_DIR]:
        if not os.path.exists(dir_):
            os.makedirs(dir_)

    model = load('rf_opcodes_freq_ngram_2.joblib')
    cv2 = load('count_vectorizer.joblib')

    for file in tqdm(os.listdir(INPUT_DIR)):
        # file = os.path.abspath(os.path.join(INPUT_DIR,file))
        file = os.path.join(INPUT_DIR,file)
        classify(model, cv2, file, threshold=args.threshold, criteria=args.criteria)

    

