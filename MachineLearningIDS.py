from tkinter import messagebox
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
import tkinter
import numpy as np
from tkinter import filedialog
import pandas as pd 
from sklearn.model_selection import train_test_split 
from sklearn.metrics import accuracy_score 
import matplotlib.pyplot as plt
from sklearn.naive_bayes import BernoulliNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn import preprocessing
import os
from sklearn import svm
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score

main = tkinter.Tk()
main.title("Detection of Cyber Attack in Network using Machine Learning Techniques")
main.geometry("1300x1200")

svm_arr = []
lr_arr = []
dt_arr = []
rf_arr = []
mlp_arr = []
nb_arr = []
knn_arr = []
global r2l,u2r,probe
global filename
global normal,dos,backdoor,reconnaissance,fuzzers,exploits,generic
global knn_acc,nb_acc,tree_acc,random_acc,svm_acc,mlp_acc
global anomaly
global X, Y, X_train, X_test, y_train, y_test
global train
def upload():
    global r2l,u2r,probe
    global anomaly
    global filename
    global train
    global X, Y, X_train, X_test, y_train, y_test
    global normal,dos,backdoor,reconnaissance,fuzzers,exploits,generic
    filename = filedialog.askopenfilename(initialdir = "datasets")
    fname = os.path.basename(filename)
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END,fname+' dataset loaded\n')
    le = preprocessing.LabelEncoder()
    if fname == 'UNSW_NB15.csv':
        train = pd.read_csv(filename)
        normal = sum(train['attack_cat'] == 'Normal')
        reconnaissance = sum(train['attack_cat'] == 'Reconnaissance')
        fuzzers = sum(train['attack_cat'] == 'Fuzzers')
        exploits = sum(train['attack_cat'] == 'Exploits')
        dos = sum(train['attack_cat'] == 'DoS')
        backdoor = sum(train['attack_cat'] == 'Backdoor')
        generic = sum(train['attack_cat'] == 'Generic')
        train['proto'] = le.fit_transform(train['proto'])
        train['service'] = le.fit_transform(train['service'])
        train['state'] = le.fit_transform(train['state'])
        train['attack_cat'] = le.fit_transform(train['attack_cat'])
        text.insert(END,'UNSW_NB15 Dataset Details\n')
        text.insert(END,'Total Normal Packets         : '+str(normal)+"\n")
        text.insert(END,'Total Reconnaissance Packets : '+str(reconnaissance)+"\n")
        text.insert(END,'Total Fuzzers Packets        : '+str(fuzzers)+"\n")
        text.insert(END,'Total Exploits Packets       : '+str(exploits)+"\n")
        text.insert(END,'Total DOS Packets            : '+str(dos)+"\n")
        text.insert(END,'Total Backdoor Packets       : '+str(backdoor)+"\n")
        text.insert(END,'Total Generic Packets        : '+str(generic)+"\n\n")
        cor = train.corr()
        cor_target = abs(cor["attack_cat"])
        relevant_features = cor_target[cor_target>0.05]
        selected = []
        for name,values in relevant_features.iteritems():
            selected.append(name)
        columns = train.columns.values.tolist()
        
        text.insert(END,"Total features in UNSW_NB15 dataset is      : "+str(len(columns))+"\n")
        text.insert(END,"Selected features after applying Filters is : "+str(len(selected))+"\n\n")
        text.insert(END,"Names of selected columns or features\n\n")
        text.insert(END,selected)
        for i in range(len(columns)):
            if columns[i] not in selected:
                train.drop(columns[i],axis=1,inplace=True)
    cols = train.shape[1]

    X = train.values[:, 0:cols-1] 
    Y = train.values[:, cols-1]
    Y = Y.astype('int')
    indices = np.arange(X.shape[0])
    np.random.shuffle(indices)
    X = X[indices]
    Y = Y[indices]
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size = 0.2, random_state = 0)

    print(X.shape)
    

    text.insert(END,"UNSW_NB15 Train & Test Model Generated\n\n")
    text.insert(END,"Total Dataset Size : "+str(len(X))+"\n")
    text.insert(END,"Splitted Training Size : "+str(len(X_train))+"\n")
    text.insert(END,"Splitted Test Size : "+str(len(X_test))+"\n\n\n")


    

    

def decisionTree():
    text.delete('1.0', END)
    global tree_acc,dtc
    dtc = DecisionTreeClassifier(random_state=0)
    dtc.fit(X_train, y_train)
    prediction_data = dtc.predict(X_test)
    tree_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"Decision Tree Accuracy : "+str(tree_acc)+"\n")
    dt_precision = precision_score(y_test, prediction_data,average='macro') * 100
    dt_recall = recall_score(y_test, prediction_data,average='macro') * 100
    dt_fmeasure = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"DT Precision : "+str(dt_precision)+"\n")
    text.insert(END,"DT Recall : "+str(dt_recall)+"\n")
    text.insert(END,"DT FMeasure : "+str(dt_fmeasure)+"\n\n")
    dt_arr.append(tree_acc)
    
def randomForest():
    global random_acc,rfc1
    rfc1 = RandomForestClassifier(n_estimators=2, random_state=0)
    rfc1.fit(X_train, y_train)
    prediction_data = rfc1.predict(X_test) 
    random_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"Random Forest Accuracy : "+str(random_acc)+"\n")
    rf_precision = precision_score(y_test, prediction_data,average='macro') * 100
    rf_recall = recall_score(y_test, prediction_data,average='macro') * 100
    rf_fmeasure = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"RF Precision : "+str(rf_precision)+"\n")
    text.insert(END,"RF Recall : "+str(rf_recall)+"\n")
    text.insert(END,"RF FMeasure : "+str(rf_fmeasure)+"\n\n")
    rf_arr.append(random_acc)


def svmAlgorithm():
    global svm_acc
    tempX = []
    tempY = []
    for i in range(0,950):
        tempX.append(X_train[i])
        tempY.append(y_train[i])
    tempX = np.asarray(tempX)
    tempY = np.asarray(tempY)
    rfc = svm.SVC()
    rfc.fit(tempX, tempY)
    prediction_data = rfc.predict(X_test) 
    svm_acc = accuracy_score(y_test,prediction_data)*100
    svm_precision = precision_score(y_test, prediction_data,average='macro') * 100
    svm_recall = recall_score(y_test, prediction_data,average='macro') * 100
    svm_fmeasure = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"SVM Accuracy : "+str(svm_acc)+"\n")
    text.insert(END,"SVM Precision : "+str(svm_precision)+"\n")
    text.insert(END,"SVM Recall : "+str(svm_recall)+"\n")
    text.insert(END,"SVM FMeasure : "+str(svm_fmeasure)+"\n\n")
    svm_arr.append(svm_acc)

def predictType():
    filename = filedialog.askopenfilename(initialdir="datasets")
    text.delete('1.0', END)
    text.insert(END,filename+" loaded\n");
    le = preprocessing.LabelEncoder()
    test = pd.read_csv(filename)
    test['proto'] = le.fit_transform(test['proto'])
    test['service'] = le.fit_transform(test['service'])
    test['state'] = le.fit_transform(test['state'])
    test['attack_cat'] = le.fit_transform(test['attack_cat'])      
    
    print("Test shape before correlation-->",test.shape)
    print(test.head())

    cor = test.corr()
    cor_target = abs(cor["attack_cat"])
    relevant_features = cor_target[cor_target>0.05]
    selected = []
    for name,values in relevant_features.iteritems():
        selected.append(name)
    columns = test.columns.values.tolist()


    for i in range(len(columns)):
        if columns[i] not in selected:
            test.drop(columns[i],axis=1,inplace=True)
            
    cols = test.shape[1]

    test = test.values[:, 0:cols]
    
    print("Test shape-->",test.shape)
    predict = rfc1.predict(test)
    
    print(predict)
    for i in range(len(test)):
        if predict[i] == 0:
            text.insert(END,str(test[i])+" Normal\n\n")
        if predict[i] == 1:
            text.insert(END,str(test[i])+" : Attack Detected\n\n")
    
def attackGraph():
    height = [normal,dos,backdoor,reconnaissance,fuzzers,exploits,generic]
    bars = ('Normal','DOS','Backdoor','Reconnaissance','Fuzzers','Exploits','Generic')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()

def graph():
    plt.figure(figsize=(10,6))
    plt.grid(True)
    plt.xlabel('Datasets')
    plt.ylabel('Accuracy')
    plt.plot(svm_arr, 'ro-', color = 'indigo')
    plt.plot(rf_arr, 'ro-', color = 'green')
    plt.plot(dt_arr, 'ro-', color = 'orange')
    
    
    plt.legend(['SVM', 'Random Forest','Decision Tree'], loc='lower left')
    #plt.xticks(wordloss.index)
    plt.title('Accuracy Comparison Graph')
    plt.show()

font = ('times', 16, 'bold')
title = Label(main, text='Detection of Cyber Attack in Network using Machine Learning Techniques')
title.config(bg='dark goldenrod', fg='white')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')
upload = Button(main, text="Upload IDS Dataset", command=upload)
upload.place(x=700,y=100)
upload.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='DarkOrange1', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=700,y=150)

decisionButton = Button(main, text="Run Decision Tree Algorithm", command=decisionTree)
decisionButton.place(x=700,y=200)
decisionButton.config(font=font1) 


randomButton = Button(main, text="Run Random Forest Algorithm", command=randomForest)
randomButton.place(x=700,y=250)
randomButton.config(font=font1)

stochasticButton = Button(main, text="Run SVM Algorithm", command=svmAlgorithm)
stochasticButton.place(x=700,y=300)
stochasticButton.config(font=font1)

graphButton = Button(main, text="Accuracy Graph", command=graph)
graphButton.place(x=700,y=350)
graphButton.config(font=font1)

attackgraphButton = Button(main, text="Attack Type Graph", command=attackGraph)
attackgraphButton.place(x=700,y=400)
attackgraphButton.config(font=font1)

predictButton = Button(main, text="Predict", command=predictType)
predictButton.place(x=700,y=450)
predictButton.config(font=font1)

font1 = ('times', 12, 'bold')
text=Text(main,height=30,width=80)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=font1)


main.config(bg='turquoise')
main.mainloop()
