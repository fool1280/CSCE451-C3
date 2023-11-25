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
from joblib import dump, load

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

corpus = []
y = []

if ((path.exists('data.npz'))):
    data = np.load('data.npz', allow_pickle=True)
    corpus = data['corpus']
    y = np.array(data['y'])
else:

    for name in mal_file_nos:
        data = pd.read_csv(file_path_malware + "/Mal_file" + str(name) + ".csv", engine='python', on_bad_lines='warn')
        data.drop(data.columns[data.columns.str.contains('unnamed',case = False)],axis = 1, inplace = True)
        opcode = (data["Opcode"].dropna().tolist())
        opc = " ".join(opcode)
        hashValue = hash_sent(opc.encode('utf-8'))
        if hashValue not in hashset_malware:
            corpus.append(opc)
            hashset_malware.add(hashValue)
            y.append(1)

    for name in malw_nos:
        data = pd.read_csv(file_path_malware + "/Malw_" + str(name) + ".csv", engine='python', on_bad_lines='warn')
        data.drop(data.columns[data.columns.str.contains('unnamed',case = False)],axis = 1, inplace = True)
        opcode = (data["Opcode"].dropna().tolist())
        opc = " ".join(opcode)
        hashValue = hash_sent(opc.encode('utf-8'))
        if hashValue not in hashset_malware:
            corpus.append(opc)
            hashset_malware.add(hashValue)
            y.append(1)

    for name in beni_nos:
        data = pd.read_csv(file_path_benign + "/Beni" + str(name) + ".csv", engine='python', on_bad_lines='warn')
        data.drop(data.columns[data.columns.str.contains('unnamed',case = False)],axis = 1, inplace = True)
        opcode = (data["Opcode"].dropna().tolist())
        opc = " ".join(opcode)
        hashValue = hash_sent(opc.encode('utf-8'))
        if hashValue not in hashset_benign:
            corpus.append(opc)
            hashset_benign.add(hashValue)
            y.append(0)

    for name in ben_nos:
        data = pd.read_csv(file_path_benign + "/Ben" + str(name) + ".csv", engine='python', on_bad_lines='warn')
        data.drop(data.columns[data.columns.str.contains('unnamed',case = False)],axis = 1, inplace = True)
        opcode = (data["Opcode"].dropna().tolist())
        opc = " ".join(opcode)
        hashValue = hash_sent(opc.encode('utf-8'))
        if hashValue not in hashset_benign:
            corpus.append(opc)
            hashset_benign.add(hashValue)
            y.append(0)
    corpus_array = np.array(corpus, dtype=object)
    y_array = np.array(y)
    np.savez('data.npz', corpus=corpus_array, y=y_array)
print("Load data complete")
print("Corpus length: ", len(corpus))
print("y length: ", len(y))

# CountVectorizer converts the Opcode sequence to a matrix of token counts
# CountVectorizer creates the Dataset to be fed into the Machine Learning Algorithms.
# The N-Gram size is given as parameter.
# X1 consists of Opcode as Column names(N-Gram=1) and either Opcode Count or Opcode Frequency as its row data.
# X2 consists of Opcodes as Column names(N-Gram=2) and either Opcode Count or Opcode Frequency as its row data.

cv1 = CountVectorizer()
X1 = cv1.fit_transform(corpus).toarray()
cv2 = CountVectorizer(ngram_range=(2,2))
X2 = cv2.fit_transform(corpus).toarray()

dump(cv2, 'count_vectorizer.joblib')

# X11 is the Dataset consisting of Opcode Count with N-Gram=1 as it's data.
# X21 is the Dataset consisting of Opcode Count with N-Gram=2 as it's data.
# They are split into Training and Test Data(Although they are split directly from X1 and X2).

X11_train, X11_test, y11_train, y11_test = train_test_split(X1, y, test_size = 0.25)
X21_train, X21_test, y21_train, y21_test = train_test_split(X2, y, test_size = 0.25)

# X1 and X2 are converted into Frequency form (Mentioned in more detail in README.md).
# X12 is the Dataset consisting of Opcode Frequency with N-Gram=1 as it's data.
# X22 is the Dataset consisting of Opcode Frequency with N-Gram=2 as it's data.
# They are split into Training and Test Data(Although they are split directly from v1 and v2).

v1 = np.array(X1).astype(np.float32)
for i in range(len(corpus)):
    s = sum(X1[i])
    v1[i] = ((X1[i]/s)*100).astype(np.float32)

X12_train, X12_test, y12_train, y12_test = train_test_split(v1, y, test_size = 0.25)

v2 = np.array(X2).astype(np.float32)
for i in range(len(corpus)):
    s = sum(X2[i])
    v2[i] = ((X2[i]/s)*100).astype(np.float32)

X22_train, X22_test, y22_train, y22_test = train_test_split(v2, y, test_size = 0.25)

print("Test, train, split complete")

print("GB \n")
classifierGB11 = GaussianNB()
classifierGB11.fit(X11_train, y11_train)
y11_pred = classifierGB11.predict(X11_test)
cm11 = confusion_matrix(y11_test, y11_pred)
print(cm11)
print(accuracy_score(y11_test, y11_pred))
print('\n')

classifierGB12 = GaussianNB()
classifierGB12.fit(X12_train, y12_train)
y12_pred = classifierGB12.predict(X12_test)
cm12 = confusion_matrix(y12_test, y12_pred)
print(cm12)
print(accuracy_score(y12_test, y12_pred))
print('\n')

classifierGB21 = GaussianNB()
classifierGB21.fit(X21_train, y21_train)
y21_pred = classifierGB21.predict(X21_test)
cm21 = confusion_matrix(y21_test, y21_pred)
print(cm21)
print(accuracy_score(y21_test, y21_pred))
print('\n')

classifierGB22 = GaussianNB()
classifierGB22.fit(X22_train, y22_train)
y22_pred = classifierGB22.predict(X22_test)
cm22 = confusion_matrix(y22_test, y22_pred)
print(cm22)
print(accuracy_score(y22_test, y22_pred))
print('\n')

print("SVC \n")
classifiersvc11 = SVC(kernel = 'linear', random_state = 0)
classifiersvc11.fit(X11_train, y11_train)
classifiersvc12= SVC(kernel = 'linear', random_state = 0)
classifiersvc12.fit(X12_train, y12_train)
classifiersvc21 = SVC(kernel = 'linear', random_state = 0)
classifiersvc21.fit(X21_train, y21_train)
classifiersvc22 = SVC(kernel = 'linear', random_state = 0)
classifiersvc22.fit(X22_train, y22_train)

ysvc11_pred=classifiersvc11.predict(X11_test)
ysvc12_pred=classifiersvc12.predict(X12_test)
ysvc21_pred=classifiersvc21.predict(X21_test)
ysvc22_pred=classifiersvc22.predict(X22_test)

cm11 = confusion_matrix(y11_test, ysvc11_pred)
print(cm11)
print(accuracy_score(y11_test, ysvc11_pred))
print('\n')
cm12 = confusion_matrix(y12_test, ysvc12_pred)
print(cm12)
print('\n')
print(accuracy_score(y12_test, ysvc12_pred))
cm21 = confusion_matrix(y21_test, ysvc21_pred)
print(cm21)
print('\n')
print(accuracy_score(y21_test, ysvc21_pred))
cm22 = confusion_matrix(y22_test, ysvc22_pred)
print(cm22)
print(accuracy_score(y22_test, ysvc22_pred))
print('\n')

print("RF \n")
classifierrf11 = RandomForestClassifier(n_estimators = 150, criterion = 'entropy', random_state = 0)
classifierrf11.fit(X11_train, y11_train)
classifierrf12= RandomForestClassifier(n_estimators = 150, criterion = 'entropy', random_state = 0)
classifierrf12.fit(X12_train, y12_train)
classifierrf21 = RandomForestClassifier(n_estimators = 150, criterion = 'entropy', random_state = 0)
classifierrf21.fit(X21_train, y21_train)
classifierrf22 = RandomForestClassifier(n_estimators = 150, criterion = 'entropy', random_state = 0)
classifierrf22.fit(X22_train, y22_train)

yrf11_pred=classifierrf11.predict(X11_test)
yrf12_pred=classifierrf12.predict(X12_test)
yrf21_pred=classifierrf21.predict(X21_test)
yrf22_pred=classifierrf22.predict(X22_test)

dump(classifierrf22, 'rf_opcodes_freq_ngram_2.joblib')

cm11 = confusion_matrix(y11_test, yrf11_pred)
print(cm11)
print(accuracy_score(y11_test, yrf11_pred))
print('\n')
cm12 = confusion_matrix(y12_test, yrf12_pred)
print(cm12)
print(accuracy_score(y12_test, yrf12_pred))
print('\n')
cm21 = confusion_matrix(y21_test, yrf21_pred)
print(cm21)
print(accuracy_score(y21_test, yrf21_pred))
print('\n')
cm22 = confusion_matrix(y22_test, yrf22_pred)
print(cm22)
print(accuracy_score(y22_test, yrf22_pred))
print('\n')

print("SVM \n")
classifiersvm11 = SVC(kernel = 'rbf', random_state = 0)
classifiersvm11.fit(X11_train, y11_train)
classifiersvm12= SVC(kernel = 'rbf', random_state = 0)
classifiersvm12.fit(X12_train, y12_train)
classifiersvm21 = SVC(kernel = 'rbf', random_state = 0)
classifiersvm21.fit(X21_train, y21_train)
classifiersvm22 = SVC(kernel = 'rbf', random_state = 0)
classifiersvm22.fit(X22_train, y22_train)

ysvm11_pred=classifiersvm11.predict(X11_test)
ysvm12_pred=classifiersvm12.predict(X12_test)
ysvm21_pred=classifiersvm21.predict(X21_test)
ysvm22_pred=classifiersvm22.predict(X22_test)

cm11 = confusion_matrix(y11_test, ysvm11_pred)
print(cm11)
print(accuracy_score(y11_test, ysvm11_pred))
print('\n')
cm12 = confusion_matrix(y12_test, ysvm12_pred)
print(cm12)
print(accuracy_score(y12_test, ysvm12_pred))
print('\n')
cm21 = confusion_matrix(y21_test, ysvm21_pred)
print(cm21)
print(accuracy_score(y21_test, ysvm21_pred))
print('\n')
cm22 = confusion_matrix(y22_test, ysvm22_pred)
print(cm22)
print(accuracy_score(y22_test, ysvm22_pred))
print('\n')

print("DT \n")
classifierdt11 =DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
classifierdt11.fit(X11_train, y11_train)
classifierdt12= DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
classifierdt12.fit(X12_train, y12_train)
classifierdt21 = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
classifierdt21.fit(X21_train, y21_train)
classifierdt22 = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
classifierdt22.fit(X22_train, y22_train)

ydt11_pred=classifierdt11.predict(X11_test)
ydt12_pred=classifierdt12.predict(X12_test)
ydt21_pred=classifierdt21.predict(X21_test)
ydt22_pred=classifierdt22.predict(X22_test)

cm11 = confusion_matrix(y11_test, ydt11_pred)
print(cm11)
print(accuracy_score(y11_test, ydt11_pred))
print('\n')
cm12 = confusion_matrix(y12_test, ydt12_pred)
print(cm12)
print(accuracy_score(y12_test, ydt12_pred))
print('\n')
cm21 = confusion_matrix(y21_test, ydt21_pred)
print(cm21)
print(accuracy_score(y21_test, ydt21_pred))
print('\n')
cm22 = confusion_matrix(y22_test, ydt22_pred)
print(cm22)
print(accuracy_score(y22_test, ydt22_pred))
print('\n')

print("KNN \n")
classifierknn11 =KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2)
classifierknn11.fit(X11_train, y11_train)
classifierknn12= KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2)
classifierknn12.fit(X12_train, y12_train)
classifierknn21 =KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2)
classifierknn21.fit(X21_train, y21_train)
classifierknn22 =KNeighborsClassifier(n_neighbors = 5, metric = 'minkowski', p = 2)
classifierknn22.fit(X22_train, y22_train)

yknn11_pred=classifierknn11.predict(X11_test)
yknn12_pred=classifierknn12.predict(X12_test)
yknn21_pred=classifierknn21.predict(X21_test)
yknn22_pred=classifierknn22.predict(X22_test)

cm11 = confusion_matrix(y11_test, yknn11_pred)
print(cm11)
print(accuracy_score(y11_test, yknn11_pred))
print('\n')
cm12 = confusion_matrix(y12_test, yknn12_pred)
print(cm12)
print(accuracy_score(y12_test, yknn12_pred))
print('\n')
cm21 = confusion_matrix(y21_test, yknn21_pred)
print(cm21)
print(accuracy_score(y21_test, yknn21_pred))
print('\n')
cm22 = confusion_matrix(y22_test, yknn22_pred)
print(cm22)
print(accuracy_score(y22_test, yknn22_pred))
print('\n')

