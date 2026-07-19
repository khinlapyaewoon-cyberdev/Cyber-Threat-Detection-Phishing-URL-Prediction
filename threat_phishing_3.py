# ==========================================================
# Cyber WebX Threat Intelligence Analyzer
# Part 1/2
#
# Modes:
# 1. Recon Threat Detection
# 2. Phishing URL Prediction
# ==========================================================


import os
import re
import json
import joblib
import pandas as pd
import streamlit as st
import tldextract
import matplotlib.pyplot as plt

from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# ==========================================================
# CONFIGURATION
# ==========================================================


RECON_FOLDER = "Websites"


MODEL_FILE = "phishing_nb.pkl"

ENCODER_FILE = "label_encoder.pkl"

FEATURE_FILE = "feature_columns.pkl"





# ==========================================================
# WEBSITE DOMAIN DATABASE
# 30 RECON TARGETS
# ==========================================================


WEBSITE_DOMAINS = [

"hackthissite.org",
"pdfcoffee.com",
"mail.ucspyay.edu.mm",
"api.ucspyay.edu.mm",

"hackerone.com",
"testphp.vulnweb.com",
"demo.testfire.net",

"bank.example.com",
"shop.example.com",
"cloud.example.com",

"api.example.com",
"dev.example.com",
"stage.example.com",

"vpn.example.com",
"admin.example.com",

"crm.example.com",
"erp.example.com",
"hr.example.com",

"git.example.com",
"repo.example.com",

"docker.example.com",
"k8s.example.com",

"mobile.example.com",
"app.example.com",

"login.example.com",
"auth.example.com",

"payment.example.com",
"gateway.example.com",

"support.example.com",
"mail.example.com"

]





# ==========================================================
# THREAT SIGNAL DATABASE
# ==========================================================


THREAT_SIGNALS = {


# Access & Authentication

"Exposed Administrative Interface":
[
"/admin",
"/dashboard",
"/manage"
],


"Authentication Weakness":
[
"no authentication",
"anonymous",
"weak password"
],


"Credential Exposure":
[
"api_key",
"password=",
"token=",
"secret="
],



# Network

"Open Network Services":
[
"open port",
"0.0.0.0",
"listening on"
],


"Unrestricted Internal Service":
[
"internal",
"localhost exposed"
],


"Cloud Storage Exposure":
[
"s3 bucket",
"public bucket",
"blob storage"
],



# Software

"Outdated Software":
[
"deprecated",
"end of life",
"version 1."
],


"Legacy Protocol Usage":
[
"tls 1.0",
"tls 1.1",
"ssl v3"
],



# Application Security

"Debug Artifact Exposure":
[
"stack trace",
"traceback",
"debug"
],


"Insecure Security Headers":
[
"missing security headers",
"x-frame-options"
],


"CORS Misconfiguration":
[
"access-control-allow-origin",
"credentials=true"
],



# Data Exposure

"Metadata Disclosure":
[
"server:",
"x-powered-by"
],


"Sensitive File Exposure":
[
".env",
".git",
"backup.sql"
],



# Access Control

"Excessive Privilege Assignment":
[
"admin privileges",
"root access"
],


"Improper Access Control":
[
"unauthorized access",
"forbidden bypass"
],



# API

"Exposed API Endpoint":
[
"/api/",
"/v1/",
"/v2/"
],


"GraphQL Introspection Enabled":
[
"__schema",
"__type"
],



# Social Engineering

"Phishing Susceptibility":
[
"click here",
"verify your account",
"password reset link"
],


"Malicious Email Indicators":
[
"attachment.exe",
"macro enabled",
"urgent request"
],



# Malware

"Backdoor Remote Access":
[
"reverse shell",
"webshell",
"rce"
],


"Persistence Mechanisms":
[
"startup folder",
"cron job",
"registry autorun"
],



# Supply Chain

"Third Party Compromise":
[
"npm package",
"python dependency",
"malicious library"
],



# API Abuse

"Excessive API Calls":
[
"rate limit exceeded",
"api abuse",
"flood request"
],


"Token Leakage":
[
"bearer token",
"oauth token exposed"
],



# Cloud Container

"Misconfigured Cloud IAM":
[
"s3 policy public",
"iam overly permissive",
"bucket policy open"
],


"Container Escape Risk":
[
"docker socket",
"privileged container",
"kubernetes misconfig"
],



# Network Movement

"VPN Remote Access Weakness":
[
"default vpn creds",
"openvpn misconfig",
"pptp exposed"
],


"SMB File Share Exposure":
[
"smb share open",
"anonymous smb access"
],



# Privacy

"PII Exposure":
[
"ssn",
"credit card",
"passport number"
],


"Database Leakage":
[
"mysql dump",
"mongodb exposed",
"postgres backup"
],



# Encryption

"Weak Encryption TLS Misconfiguration":
[
"sslv3",
"rc4 cipher",
"weak dh key"
],


"Unprotected Secrets in Repositories":
[
".env",
".pem",
"private.key"
]


}







# ==========================================================
# RECON FILE FINDER
# ==========================================================


def find_recon_file(domain):


    if not os.path.exists(RECON_FOLDER):

        return None



    for filename in os.listdir(RECON_FOLDER):


        if domain.lower() in filename.lower():


            return os.path.join(
                RECON_FOLDER,
                filename
            )



    return None







# ==========================================================
# THREAT DETECTION ENGINE
# ==========================================================


def detect_signals(text):


    findings = {}


    lines=text.splitlines()



    for signal,patterns in THREAT_SIGNALS.items():


        seen_patterns=set()

        evidence_list=[]



        for line in lines:


            clean=line.strip().lower()



            for p in patterns:


                if p.lower() in clean:


                    seen_patterns.add(p)



                    evidence_list.append(

                    {

                    "pattern":p,

                    "line":line

                    }

                    )



        if evidence_list:

           findings[signal] = {

               "patterns": list(seen_patterns),

               "evidence": evidence_list,

               "lines": [
                   e["line"]
                   for e in evidence_list
                ]

             }



    return findings







# ==========================================================
# PHISHING RULE ENGINE
# ==========================================================


# ==========================================================
# PHISHING RULE DATABASE
# ==========================================================

PHISHING_RULES = {

# ----------------------------------------------------------
# Credential Theft
# ----------------------------------------------------------

"Credential Harvesting":[

"login",
"signin",
"sign-in",
"logon",
"password",
"passwd",
"verify",
"verification",
"confirm",
"authenticate",
"authentication",
"account",
"reset",
"unlock",
"security-check"

],

# ----------------------------------------------------------
# Banking
# ----------------------------------------------------------

"Financial Brand Impersonation":[

"bank",
"paypal",
"visa",
"mastercard",
"payment",
"wallet",
"invoice",
"billing",
"refund",
"crypto",
"coinbase",
"binance",
"kraken"

],

# ----------------------------------------------------------
# Microsoft
# ----------------------------------------------------------

"Microsoft Account Phishing":[

"office365",
"office-365",
"microsoft",
"azure",
"live",
"outlook",
"exchange",
"sharepoint",
"onedrive",
"teams"

],

# ----------------------------------------------------------
# Google
# ----------------------------------------------------------

"Google Account Phishing":[

"gmail",
"google",
"drive",
"docs",
"gdocs",
"googleusercontent",
"workspace"

],

# ----------------------------------------------------------
# Apple
# ----------------------------------------------------------

"Apple ID Phishing":[

"appleid",
"icloud",
"apple",
"itunes"

],

# ----------------------------------------------------------
# Social Media
# ----------------------------------------------------------

"Social Media Phishing":[

"facebook",
"instagram",
"whatsapp",
"telegram",
"twitter",
"x",
"linkedin",
"tiktok",
"snapchat",
"discord"

],

# ----------------------------------------------------------
# Package Delivery
# ----------------------------------------------------------

"Parcel Delivery Scam":[

"dhl",
"fedex",
"ups",
"usps",
"shipping",
"delivery",
"parcel",
"tracking"

],

# ----------------------------------------------------------
# Fake Invoice
# ----------------------------------------------------------

"Invoice Scam":[

"invoice",
"receipt",
"purchase",
"billing",
"payment",
"statement"

],

# ----------------------------------------------------------
# Malware
# ----------------------------------------------------------

"Malware Delivery":[

".exe",
".dll",
".apk",
".bat",
".vbs",
".scr",
".zip",
".rar",
".7z",
".iso",
".img",
".msi"

],

# ----------------------------------------------------------
# Fake Update
# ----------------------------------------------------------

"Fake Software Update":[

"update",
"upgrade",
"download",
"installer",
"install",
"flash",
"java-update",
"chrome-update"

],

# ----------------------------------------------------------
# OAuth
# ----------------------------------------------------------

"OAuth Token Theft":[

"oauth",
"authorize",
"callback",
"access_token",
"refresh_token",
"client_id"

],

# ----------------------------------------------------------
# URL Shortener
# ----------------------------------------------------------

"Short URL Abuse":[

"bit.ly",
"tinyurl",
"goo.gl",
"ow.ly",
"t.co",
"cutt.ly",
"is.gd",
"rb.gy"

],

# ----------------------------------------------------------
# Domain Tricks
# ----------------------------------------------------------

"Suspicious Domain Pattern":[

"xn--",
".xyz",
".top",
".tk",
".cf",
".ml",
".ga",
".gq"

],

# ----------------------------------------------------------
# Remote Access
# ----------------------------------------------------------

"Remote Access Scam":[

"teamviewer",
"anydesk",
"ultraviewer",
"quicksupport"

],

# ----------------------------------------------------------
# Gift Scam
# ----------------------------------------------------------

"Prize Giveaway":[

"gift",
"winner",
"won",
"reward",
"bonus",
"claim",
"coupon",
"free"

],

# ----------------------------------------------------------
# Employment Scam
# ----------------------------------------------------------

"Job Scam":[

"job",
"hiring",
"career",
"interview",
"resume",
"cv",
"employment"

],

# ----------------------------------------------------------
# Tech Support Scam
# ----------------------------------------------------------

"Technical Support Scam":[

"support",
"helpdesk",
"call-now",
"virus-alert",
"windows-defender",
"security-alert"

],

# ----------------------------------------------------------
# Government Scam
# ----------------------------------------------------------

"Government Impersonation":[

"irs",
"tax",
"passport",
"immigration",
"government",
"police",
"court"

],

# ----------------------------------------------------------
# Charity Scam
# ----------------------------------------------------------

"Donation Scam":[

"donation",
"charity",
"relief",
"fundraising"

],

# ----------------------------------------------------------
# Romance Scam
# ----------------------------------------------------------

"Romance Scam":[

"dating",
"love",
"soulmate"

]

}





# ==========================================================
# TRUSTED DOMAINS
# ==========================================================

TRUSTED_DOMAINS = [

    # Search
    "google.com",
    "bing.com",
    "yahoo.com",
    "duckduckgo.com",

    # Microsoft
    "microsoft.com",
    "office.com",
    "office365.com",
    "live.com",
    "outlook.com",
    "azure.com",

    # Apple
    "apple.com",
    "icloud.com",

    # Amazon
    "amazon.com",
    "aws.amazon.com",

    # Git
    "github.com",
    "gitlab.com",
    "bitbucket.org",

    # Social
    "facebook.com",
    "instagram.com",
    "messenger.com",
    "threads.net",
    "whatsapp.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "reddit.com",

    # Video
    "youtube.com",
    "vimeo.com",
    "netflix.com",
    "spotify.com",

    # Cloud
    "dropbox.com",
    "box.com",
    "mega.nz",

    # Payment
    "paypal.com",
    "stripe.com",
    "visa.com",
    "mastercard.com",

    # Crypto
    "coinbase.com",
    "binance.com",
    "kraken.com",

    # Shopping
    "ebay.com",
    "aliexpress.com",

    # Education
    "coursera.org",
    "edx.org",
    "udemy.com",

    # Developer
    "stackoverflow.com",
    "python.org",
    "docker.com",
    "kubernetes.io",

    # Security
    "virustotal.com",
    "abuseipdb.com",
    "cisa.gov",
    "nist.gov",
    "mitre.org",
    "owasp.org",

    # Government
    "gov",
    "edu",

    # Myanmar
    "mm",
    "edu.mm",
    "gov.mm"

]


def legitimate_checks(url):

    results=[]

    domain=tldextract.extract(url).registered_domain


    if domain in TRUSTED_DOMAINS:

        results.append(
        "Known trusted domain"
        )


    return results
# ==========================================================
# Part 2/2
# Machine Learning Phishing Prediction
# + Streamlit Interface
# ==========================================================


# ==========================================================
# FILES
# ==========================================================

DATASET = "dataset_phishing_updated.csv"

MODEL_FILE = "phishing_nb.pkl"

ENCODER_FILE = "label_encoder.pkl"

FEATURE_FILE = "feature_columns.pkl"




# ==========================================================
# TRAIN MODEL
# ==========================================================

def train_model():


    df = pd.read_csv(DATASET)


    df = df.fillna(0)



    X = df.drop(
        [
            "url",
            "status"
        ],
        axis=1
    )


    y = df["status"]



    encoder = LabelEncoder()


    y = encoder.fit_transform(y)



    # -----------------------------
    # 80/20 SPLIT
    # -----------------------------

    X_train, X_test, y_train, y_test = train_test_split(

        X,

        y,

        test_size=0.4,

        random_state=42,

        stratify=y

    )



    # -----------------------------
    # TRAIN ONLY
    # -----------------------------

    model = GaussianNB()


    model.fit(

        X_train,

        y_train

    )



    # -----------------------------
    # SAVE
    # -----------------------------


    joblib.dump(
        model,
        MODEL_FILE
    )


    joblib.dump(
        encoder,
        ENCODER_FILE
    )


    joblib.dump(
        list(X.columns),
        FEATURE_FILE
    )


    print(
        "Model Training Completed"
    )




# ==========================================================
# LOAD MODEL
# ==========================================================


if not os.path.exists(MODEL_FILE) \
or not os.path.exists(ENCODER_FILE) \
or not os.path.exists(FEATURE_FILE):

    train_model()



MODEL = joblib.load(
    MODEL_FILE
)


ENCODER = joblib.load(
    ENCODER_FILE
)


FEATURE_COLUMNS = joblib.load(
    FEATURE_FILE
)





# ==========================================================
# FEATURE GENERATOR
# ==========================================================

def generate_features(url):

    data = {}

    url_lower = url.lower()

    ext = tldextract.extract(url)

    hostname = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix


    # ===============================
    # BASIC URL FEATURES
    # ===============================

    data["length_url"] = len(url)

    data["length_hostname"] = len(hostname)


    data["ip"] = int(
        bool(
            re.search(
                r"\d+\.\d+\.\d+\.\d+",
                url
            )
        )
    )


    # Character counts

    data["nb_dots"] = url.count(".")

    data["nb_hyphens"] = url.count("-")

    data["nb_at"] = url.count("@")

    data["nb_qm"] = url.count("?")

    data["nb_and"] = url.count("&")

    data["nb_or"] = url.count("|")

    data["nb_eq"] = url.count("=")

    data["nb_underscore"] = url.count("_")

    data["nb_tilde"] = url.count("~")

    data["nb_percent"] = url.count("%")

    data["nb_slash"] = url.count("/")

    data["nb_star"] = url.count("*")

    data["nb_colon"] = url.count(":")

    data["nb_comma"] = url.count(",")

    data["nb_semicolumn"] = url.count(";")

    data["nb_dollar"] = url.count("$")

    data["nb_space"] = url.count(" ")



    data["nb_www"] = int(
        "www" in url_lower
    )


    data["nb_com"] = int(
        ".com" in url_lower
    )


    data["nb_dslash"] = url.count("//")



    # ===============================
    # PATH / HTTPS
    # ===============================


    data["http_in_path"] = int(
        "http" in url_lower[8:]
    )


    data["https_token"] = int(
        "https" in url_lower
    )


    # digit ratio

    data["ratio_digits_url"] = (
        sum(c.isdigit() for c in url)
        /
        len(url)
        if len(url)>0 else 0
    )


    data["ratio_digits_host"] = (

        sum(
            c.isdigit()
            for c in hostname
        )
        /
        len(hostname)
        if len(hostname)>0 else 0

    )


    data["punycode"] = int(

        "xn--" in url_lower

    )


    data["port"] = int(

        bool(
            re.search(
                r":\d+",
                url
            )
        )

    )



    # ===============================
    # DOMAIN FEATURES
    # ===============================


    data["tld_in_path"] = int(

        suffix in url_lower

    )


    data["tld_in_subdomain"] = int(

        suffix in subdomain

    )


    data["abnormal_subdomain"] = int(

        len(subdomain.split(".")) > 2

    )


    data["nb_subdomains"] = (

        len(
            subdomain.split(".")
        )
        if subdomain
        else 0

    )


    data["prefix_suffix"] = int(

        "-" in hostname

    )


    data["random_domain"] = int(

        len(hostname)>15

        and

        not hostname.isalpha()

    )


    data["shortening_service"] = int(

        any(

            x in url_lower

            for x in [

                "bit.ly",
                "tinyurl",
                "goo.gl",
                "t.co",
                "ow.ly"

            ]

        )

    )


    data["path_extension"] = int(

        any(

            x in url_lower

            for x in [

                ".php",
                ".html",
                ".jsp",
                ".aspx"

            ]

        )

    )



    data["nb_redirection"] = url.count("redirect")


    data["nb_external_redirection"] = url.count("url=")



    # ===============================
    # WORD FEATURES
    # ===============================


    words = re.split(
        r"[^a-zA-Z0-9]",
        url
    )

    words=[x for x in words if x]


    data["length_words_raw"] = len(words)


    data["char_repeat"] = int(

        bool(
            re.search(
                r"(.)\1\1",
                url
            )
        )

    )


    word_lengths=[len(x) for x in words]


    data["shortest_words_raw"] = (

        min(word_lengths)
        if word_lengths
        else 0

    )


    data["shortest_word_host"] = len(hostname)


    data["shortest_word_path"] = (

        min(word_lengths)
        if word_lengths
        else 0

    )


    data["longest_words_raw"] = (

        max(word_lengths)
        if word_lengths
        else 0

    )


    data["longest_word_host"] = len(hostname)


    data["longest_word_path"] = (

        max(word_lengths)
        if word_lengths
        else 0

    )


    data["avg_words_raw"] = (

        sum(word_lengths)/len(word_lengths)

        if word_lengths

        else 0

    )


    data["avg_word_host"] = len(hostname)


    data["avg_word_path"] = (

        sum(word_lengths)/len(word_lengths)

        if word_lengths

        else 0

    )



    # ===============================
    # PHISHING HINTS
    # ===============================


    hints=[

        "login",
        "verify",
        "secure",
        "account",
        "update",
        "bank",
        "password",
        "confirm"

    ]


    data["phish_hints"] = sum(

        x in url_lower

        for x in hints

    )



    
    data["suspecious_tld"] = int(

        suffix in [

            "xyz",
            "top",
            "tk",
            "ml",
            "ga",
            "cf"

        ]

    )


   



    # ===============================
    # HTML RELATED FEATURES
    # ===============================

    


    data["login_form"]=int(

        "login" in url_lower

    )


    


    data["submit_email"]=int(

        "email" in url_lower

    )


    


    data["iframe"]=int(

        "iframe" in url_lower

    )


    data["popup_window"]=int(

        "popup" in url_lower

    )


    


    data["onmouseover"]=int(

        "onmouseover" in url_lower

    )


    data["right_clic"]=int(

        "rightclick" in url_lower

    )


   


    # ===============================
    # DOMAIN AGE / REPUTATION
    # ===============================




    # ===============================
    # MATCH DATASET COLUMNS
    # ===============================


    for col in FEATURE_COLUMNS:

        if col not in data:

            data[col]=0



    return pd.DataFrame(
        [data]
    )[FEATURE_COLUMNS]



# ==========================================================
# PREDICTION
# ==========================================================

def predict_url(url):


    features = generate_features(url)


    result = MODEL.predict(
        features
    )[0]


    label = ENCODER.inverse_transform(

        [

            result

        ]

    )[0]



    return label, features





# ==========================================================
# RULE BASED PHISHING CLASSIFIER
# ==========================================================


# ==========================================================
# RULE BASED PHISHING CLASSIFIER
# ==========================================================

def phishing_analysis(url):

    url = url.lower()

    results = []

    for category, keywords in PHISHING_RULES.items():

        matches = []

        for word in keywords:

            if word in url:

                matches.append(word)

        if matches:

            results.append(

                {

                    "type": category,

                    "indicators": matches

                }

            )

    return {

        "phishing_types": results

        
    }



# ==========================================================
# STREAMLIT APPLICATION
# ==========================================================


st.set_page_config(

page_title="Cyber Threat Detection & Phishing Prediction",

layout="wide"

)



st.title(
"Cyber Threat Detection & Phishing Prediction"
)




mode=st.sidebar.radio(

"Select Mode",

[
"Threat Detection",
"Phishing Prediction"
]

)





# ==========================================================
# MODE 1
# ==========================================================


# ==========================================================
# MODE 1
# ==========================================================

# ==========================================================
# MODE 1
# ==========================================================

# ==========================================================
# MODE 1
# RECON THREAT DETECTION
# ==========================================================

# ==========================================================
# MODE 1
# RECON THREAT DETECTION
# ==========================================================


# ==========================================================
# MODE 1
# RECON THREAT DETECTION
# ==========================================================


if mode == "Threat Detection":


    st.header(
        "Recon TXT Threat Detection"
    )



    domain = st.selectbox(

        "Select Website Domain",

        WEBSITE_DOMAINS

    )




    if st.button(
        "Analyze Recon"
    ):



        recon = find_recon_file(domain)




        if recon is None:


            st.error(
                "Recon TXT file not found"
            )



        else:



            with open(
                recon,
                "r",
                errors="ignore"
            ) as f:


                text = f.read()




            result = detect_signals(text)



            st.success(
                f"Loaded: {recon}"
            )




            if result:



                # ==================================================
                # CREATE INDICATOR + EVIDENCE DATA
                # ==================================================


                rows = []



                total_indicators = 0

                total_evidence = 0




                for threat, info in result.items():



                    indicator_count = len(
                        info["patterns"]
                    )



                    evidence_count = len(
                        info["evidence"]
                    )



                    rows.append({

                        "Threat": threat,

                        "Indicators": indicator_count,

                        "Evidence Lines": evidence_count

                    })



                    total_indicators += indicator_count

                    total_evidence += evidence_count






                threat_df = pd.DataFrame(rows)






                # ==================================================
                # CALCULATE TWO PERCENTAGES
                # ==================================================



                threat_df["Indicator Percentage"] = (

                    threat_df["Indicators"]

                    /

                    total_indicators

                ) * 100




                threat_df["Evidence Percentage"] = (

                    threat_df["Evidence Lines"]

                    /

                    total_evidence

                ) * 100






                # ==================================================
                # COMBINED PERCENTAGE
                # Average of Indicator + Evidence Percentage
                # ==================================================



                threat_df["Combined Percentage"] = (

                    threat_df["Indicator Percentage"]

                    +

                    threat_df["Evidence Percentage"]

                ) / 2






                # Normalize for pie chart

                threat_df["Pie Value"] = (

                    threat_df["Combined Percentage"]

                    /

                    threat_df["Combined Percentage"].sum()

                ) * 100






                # ==================================================
                # SUMMARY
                # ==================================================



                st.subheader(
                    "Detection Summary"
                )



                col1, col2, col3 = st.columns(3)



                with col1:

                    st.metric(

                        "Threat Categories",

                        len(result)

                    )



                with col2:

                    st.metric(

                        "Unique Indicators",

                        total_indicators

                    )



                with col3:

                    st.metric(

                        "Evidence Lines",

                        total_evidence

                    )







                # ==================================================
                # SINGLE COMBINED PIE CHART
                # ==================================================



                st.subheader(

                    "Combined Threat Distribution"

                )



                fig, ax = plt.subplots(

                    figsize=(10,8)

                )



                ax.pie(

                    threat_df["Pie Value"],

                    autopct="%1.1f%%",

                    startangle=90,

                    pctdistance=0.75

                )



                ax.legend(

                    threat_df["Threat"],

                    title="Threat Categories",

                    loc="center left",

                    bbox_to_anchor=(1,0.5)

                )



                ax.set_title(

                    "Threat Distribution\n"

                    "(Indicator + Evidence Based)"

                )



                st.pyplot(fig)







                # ==================================================
                # COMBINED TABLE
                # ==================================================



                st.subheader(

                    "Threat Percentage Analysis"

                )



                display_df = threat_df.drop(
                    columns=[
                        "Pie Value"
                    ]
                 ).copy()



                display_df[

                    "Indicator Percentage"

                ] = (

                    display_df[

                        "Indicator Percentage"

                    ]

                    .round(2)

                    .astype(str)

                    + "%"

                )



                display_df[

                    "Evidence Percentage"

                ] = (

                    display_df[

                        "Evidence Percentage"

                    ]

                    .round(2)

                    .astype(str)

                    + "%"

                )



                display_df[

                    "Combined Percentage"

                ] = (

                    display_df[

                        "Combined Percentage"

                    ]

                    .round(2)

                    .astype(str)

                    + "%"

                )





                st.dataframe(

                    display_df,

                    use_container_width=True,

                    hide_index=True

                )








                # ==================================================
                # FORENSIC DETAILS
                # ==================================================



                st.subheader(

                    "Detected Threat Details"

                )




                for threat, info in result.items():



                    with st.expander(

                        threat

                    ):



                        st.write(

                            "**Matched Indicators:**"

                        )



                        st.write(

                            ", ".join(

                                info["patterns"]

                            )

                        )



                        st.write(

                            f"**Indicator Count:** "

                            f"{len(info['patterns'])}"

                        )



                        st.write(

                            f"**Evidence Count:** "

                            f"{len(info['evidence'])}"

                        )



                        st.write(

                            "**Source Evidence Lines:**"

                        )



                        for evidence in info["evidence"]:


                            st.code(

                                evidence["line"]

                            )



            else:



                st.success(

                    "No threats detected."

                )
# ==========================================================
# MODE 2
# ==========================================================


else:


    st.header(
    "Phishing URL Prediction"
    )


    url=st.text_input(

    "Enter URL",
    placeholder="https://example.com"

    )



    if st.button(
        "Analyze URL"
    ):


        if url:


            prediction, features = predict_url(url)

            st.write(
               "Prediction:",
                prediction
            )

            analysis = phishing_analysis(url)

            #st.subheader("Rule Based Validation")
            #st.json(analysis)

            if analysis["phishing_types"]:

               st.error("Prediction Validation: PHISHING")

               with st.expander("Detected Phishing Types", expanded=False):

                    for item in analysis["phishing_types"]:

                        st.write(item['type'])

            else:

                st.success("Prediction Validation: LEGITIMATE")