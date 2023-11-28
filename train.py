import numpy as np
import pandas as pd
pd.options.mode.chained_assignment = None
from os import path
import hashlib
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from joblib import dump

# Function to transform data into frequency form
def to_frequency(X):
    v = np.array(X).astype(np.float32)
    for i in range(len(X)):
        s = sum(X[i])
        v[i] = ((X[i] / s) * 100).astype(np.float32)
    return v

# Function to train and evaluate a model
def train_and_evaluate(classifier, X_train, y_train, X_test, y_test):
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred)
    print(cm)
    print(accuracy)
    print('\n')
    return classifier


def load_data(file_path, names, hashset, label):
    global corpus, y
    for name in names:
        data = pd.read_csv(f"{file_path}/{name}.csv", engine='python', on_bad_lines='warn')
        data.drop(data.columns[data.columns.str.contains('unnamed', case=False)], axis=1, inplace=True)
        opcode = " ".join(data["Opcode"].dropna().tolist())
        hashValue = hash_sent(opcode.encode('utf-8'))

        if hashValue not in hashset:
            corpus.append(opcode)
            hashset.add(hashValue)
            y.append(label)

# File names are either Malw_{id}.csv, or Mal_file{id}.csv, or Beni{id}.csv, or Ben{id}.csv, with id from 1 to 504
# File path is /content/drive/MyDrive/MalwareAnalysis/ with two sub-folders Malware and Benign
beni_nos = []
ben_nos = []
mal_file_nos = []
malw_nos =[ ]
file_path_malware = './MalwareAnalysis/Malware'
file_path_benign = './MalwareAnalysis/Benign'

for i in range(1,505):
    if ((path.exists(file_path_malware + '/Malw_'+str(i)+'.csv'))):
        malw_nos.append(i)

    if ((path.exists(file_path_malware + '/Mal_file'+str(i)+'.csv'))):
        mal_file_nos.append(i)

    if ((path.exists(file_path_benign + '/Beni'+str(i)+'.csv'))):
        beni_nos.append(i)

    if ((path.exists(file_path_benign + '/Ben'+str(i)+'.csv'))):
        ben_nos.append(i)

hashset_benign = set()
hashset_malware = set()
def hash_sent(sent):
    return hashlib.md5(sent).hexdigest()

# Corpus contains unique opcode sequence, and y is label with 1 for malware and 0 for benign.
global corpus, y
corpus = []
y = []

if path.exists('data.npz'):
    data = np.load('data.npz', allow_pickle=True)
    corpus = data['corpus']
    y = np.array(data['y'])
else:
    hashset_malware = set()
    hashset_benign = set()
    load_data(file_path_malware, [f"Mal_file{name}" for name in mal_file_nos] + [f"Malw_{name}" for name in malw_nos], hashset_malware, 1)
    load_data(file_path_benign, [f"Beni{name}" for name in beni_nos] + [f"Ben{name}" for name in ben_nos], hashset_benign, 0)
    np.savez('data.npz', corpus=np.array(corpus, dtype=object), y=np.array(y))

print("Load data complete")
print("Corpus length: ", len(corpus))
print("y length: ", len(y))

# Count Vectorizers
cv1 = CountVectorizer()
cv2 = CountVectorizer(ngram_range=(2, 2))

# Transforming corpus
X1 = cv1.fit_transform(corpus).toarray()
X2 = cv2.fit_transform(corpus).toarray()
dump(cv2, 'count_vectorizer.joblib')

# Splitting data into training and test sets
X11_train, X11_test, y11_train, y11_test = train_test_split(X1, y, test_size=0.25)
X21_train, X21_test, y21_train, y21_test = train_test_split(X2, y, test_size=0.25)

# Converting to frequency form
X12_train, X12_test, y12_train, y12_test = train_test_split(to_frequency(X1), y, test_size=0.25)
X22_train, X22_test, y22_train, y22_test = train_test_split(to_frequency(X2), y, test_size=0.25)

print("Test, train, split complete")

# Model Training and Evaluation
print("Gaussian Naive Bayes \n")
train_and_evaluate(GaussianNB(), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(GaussianNB(), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(GaussianNB(), X21_train, y21_train, X21_test, y21_test)
train_and_evaluate(GaussianNB(), X22_train, y22_train, X22_test, y22_test)

print("Support Vector Classification \n")
train_and_evaluate(SVC(kernel='linear', random_state=0), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(SVC(kernel='linear', random_state=0), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(SVC(kernel='linear', random_state=0), X21_train, y21_train, X21_test, y21_test)
train_and_evaluate(SVC(kernel='linear', random_state=0), X22_train, y22_train, X22_test, y22_test)

print("Random Forest \n")
train_and_evaluate(RandomForestClassifier(n_estimators=150, criterion='entropy', random_state=0), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(RandomForestClassifier(n_estimators=150, criterion='entropy', random_state=0), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(RandomForestClassifier(n_estimators=150, criterion='entropy', random_state=0), X21_train, y21_train, X21_test, y21_test)
rf_classifier = train_and_evaluate(RandomForestClassifier(n_estimators=150, criterion='entropy', random_state=0), X22_train, y22_train, X22_test, y22_test)
dump(rf_classifier, 'rf_opcodes_freq_ngram_2.joblib')

print("Support Vector Machine \n")
train_and_evaluate(SVC(kernel = 'rbf', random_state = 0), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(SVC(kernel = 'rbf', random_state = 0), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(SVC(kernel = 'rbf', random_state = 0), X21_train, y21_train, X21_test, y21_test)
train_and_evaluate(SVC(kernel = 'rbf', random_state = 0), X22_train, y22_train, X22_test, y22_test)

print("Decision Tree \n")
train_and_evaluate(DecisionTreeClassifier(criterion = 'entropy', random_state = 0), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(DecisionTreeClassifier(criterion = 'entropy', random_state = 0), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(DecisionTreeClassifier(criterion = 'entropy', random_state = 0), X21_train, y21_train, X21_test, y21_test)
train_and_evaluate(DecisionTreeClassifier(criterion = 'entropy', random_state = 0), X22_train, y22_train, X22_test, y22_test)

print("K-Nearest Neighbors \n")
train_and_evaluate(KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2), X11_train, y11_train, X11_test, y11_test)
train_and_evaluate(KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2), X12_train, y12_train, X12_test, y12_test)
train_and_evaluate(KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2), X21_train, y21_train, X21_test, y21_test)
train_and_evaluate(KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2), X22_train, y22_train, X22_test, y22_test)
