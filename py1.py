import pandas as pd
from django.shortcuts import render
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import re
import whois
import requests
from datetime import datetime
from bs4 import BeautifulSoup
from csv import writer
import ipaddress



# returns the home page of the website: /index.html
def home(request):
    return render(request, "index.html")

# returns the result of the phishing check: /result.html
def result(request):
    def is_registered(domain_name):  # checks if the domain is registered
        try:
            w = whois.whois(domain_name)
        except Exception:
            return False
        else:
            return bool(w.domain_name)

    def is_url(url):  # checks if the url exists
        try:
            ri = requests.get(url)  # returns the page for the url if it exists
        except Exception:
            return False
        else:
            return bool(ri.url)

    url = request.POST["URL"]  # obtains user-input url from index.html
    r = []  # list to store the final result
    res = []  # list to store the final output
    if is_url(url):
        x = [[]]  # holds the deciding attributes
        url_part = re.split('://', url)  # splits url into http(s) + url
        domain = url_part[1]  # url part
        domain_part = re.split("/", domain)  # splits domain into domainname and path
        dn = domain_part[0]  # domainname
        r.append("domain name: " + dn + "\n")  # append to final result

        # ranking
        url_for_rank = "https://siterankdata.com/" + dn
        page = requests.get(url_for_rank)
        soup = BeautifulSoup(page.content, 'html.parser')
        rank = ''
        try:
            frank = soup.find('h1', class_="font-extra-bold m-t-xl m-b-xs text-success").string.split(',')
            for ra in frank:
                rank = rank + ra
        except Exception:
            rank = '10000000'
        rank = int(rank)
        x[0].append(rank)  # adding rank to deciding attributes

        # isIp
        flag = 1
        try:
            ipaddress.ip_address(dn)
        except ValueError:
            flag = 0
        x[0].append(flag)

        # valid
        if is_registered(domain):
            x[0].append(1)
        else:
            x[0].append(0)

        # activeDuration
        activetime = 0
        if is_registered(dn):
            data = whois.whois(dn)
            if type(data.creation_date) == list:
                creation_date = data.creation_date[0]
            else:
                creation_date = data.creation_date
            if creation_date is None:
                activetime = 1
            else:
                activetime = (datetime.now() - creation_date).days
        x[0].append(activetime)

        # urlLen
        x[0].append(len(url))

        # is@
        if '@' in url:
            x[0].append(1)
        else:
            x[0].append(0)

        # isredirect
        if '//' in dn:
            x[0].append(1)
        else:
            x[0].append(0)

        # haveDash
        if '-' in dn:
            x[0].append(1)
        else:
            x[0].append(0)

        # domainLen
        x[0].append(len(dn))

        # nosOfSubdomain
        count = dn.count('.')
        x[0].append(count)

        # Machine Learning
        df = pd.read_csv(r'C:\Users\shazi\OneDrive - vit.ac.in\sem7\cs\j\imple\webApp\app1\dataset.csv')  # load dataset
        X = df.drop(columns=['domain', 'label'])  # deciding attributes (X)
        Y = df['label']  # results (Y)
        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3,
                                                            random_state=10)  # splitting into training and testing data
        r.append("rank: " + str(x[0][0]) + "\n")
        r.append("ip address check: " + str(bool(x[0][1])) + "\n")
        r.append("validity check: " + str(bool(x[0][2])) + "\n")
        r.append("age: " + str(x[0][3]) + "\n")
        r.append("length of url: " + str(x[0][4]) + "\n")
        r.append("@ check: " + str(bool(x[0][5])) + "\n")
        r.append("redirection check: " + str(bool(x[0][6])) + "\n")
        r.append("- check: " + str(bool(x[0][7])) + "\n")
        r.append("length of domain: " + str(x[0][8]) + "\n")
        r.append("number of sub domains: " + str(x[0][9]) + "\n")

        lacc = 0  # accuracy score for legitimate sites
        pacc = 0  # accuracy score for phishing sites

        # accuracy and result for decision tree classifier
        model = DecisionTreeClassifier()
        model.fit(X.values, Y)
        predictions = model.predict(X_test.values)
        y1_pred = model.predict(x)
        accuracy = 100.0 * accuracy_score(Y_test, predictions)
        if y1_pred[0] == 0:
            lacc += accuracy
            pacc += (100 - accuracy)
        else:
            lacc += (100 - accuracy)
            pacc += accuracy
        r.append("decision tree classifier: " + str(accuracy) + "\n")

        # accuracy and result for random tree classifier
        model = RandomForestClassifier()
        model.fit(X.values, Y)
        predictions = model.predict(X_test.values)
        y2_pred = model.predict(x)
        accuracy = 100.0 * accuracy_score(Y_test, predictions)
        if y2_pred[0] == 0:
            lacc += accuracy
            pacc += (100 - accuracy)
        else:
            lacc += (100 - accuracy)
            pacc += accuracy
        r.append("random forest classifier: " + str(accuracy) + "\n")

        # accuracy and result for naive bayes classifier
        model = MultinomialNB(alpha=1.0)
        model.fit(X.values, Y)
        predictions = model.predict(X_test.values)
        y3_pred = model.predict(x)
        accuracy = 100.0 * accuracy_score(Y_test, predictions)
        if y3_pred[0] == 0:
            lacc += accuracy
            pacc += (100 - accuracy)
        else:
            lacc += (100 - accuracy)
            pacc += accuracy
        r.append("naive bayes classifier: " + str(accuracy) + "\n")

        # final result and analysis
        if lacc > pacc:
            msg = "The given URL " + url + " is likely to be legitimate\n"
            acc = str(lacc / 3)
            new_row = [dn] + x[0] + [1]
        elif lacc < pacc:
            msg = "The given url " + url + " is untrusted and is likely to be a scam/phishing site\n"
            acc = str(pacc / 3)
            new_row = [dn] + x[0] + [0]
        else:
            msg = "The legitimacy of the given url " + url + " is unknown\n"
            acc = str(pacc / 3)
            new_row = [dn] + x[0] + [0]
        res = res + [msg] + ["accuracy: " + acc]
        with open(r'C:\Users\shazi\OneDrive - vit.ac.in\sem7\cs\j\imple\webApp\app1\dataset.csv', 'a') as f_object:  # updating dataset
            p = writer(f_object)
            p.writerow(new_row)
            f_object.close()
    else:  # if the url doesn't exist
        r.append(
            "Connection to the given url could not be made. Please check if the url is valid and accessible by your network.")
    return render(request, "result.html", {"det": r, "res": res})  # sends results to result.html
