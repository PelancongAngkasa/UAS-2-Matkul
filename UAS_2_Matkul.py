import streamlit as st
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import pickle
from streamlit_lottie import st_lottie
from streamlit_option_menu import option_menu
from streamlit_carousel import carousel
import requests
import pandas as pd
import ipaddress
import re
import matplotlib.pyplot as plt


st.set_page_config(page_title="ATHGUARD", layout='wide')

def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


animasi = load_lottieurl("https://lottie.host/6216d2ef-9e65-41e8-b4fd-1dd0b1e2016f/xMTkroTlTA.json")

st.image('ATHGUARD-tp.png', width=500)
selected = option_menu(
    menu_title = "Main Menu",
    options=["Home", "Detect", "Contacts"],
    icons=["house","binoculars","envelope"],
    menu_icon = "cast",
    default_index = 0,
    orientation="horizontal",
)

if selected == "Home":
        with st.container():
            gambar_slide = [
                dict(
                    title="Deteksi Canggih",
                    text="Kami menggunakan teknologi deteksi terkini untuk mengidentifikasi tautan phishing dengan akurasi tinggi.",
                    interval=None,
                    img="https://img.freepik.com/free-photo/global-business-internet-network-connection-iot-internet-things-business-intelligence-concept-busines-global-network-futuristic-technology-background-ai-generative_1258-176762.jpg?w=826&t=st=1706253599~exp=1706254199~hmac=d7a33538e47a1e4359d28e5e32b7fd0ebd96dade9a510e27e31e7f5bfc9ec524",
                ),
                dict(
                    title="Pembaruan Berkala",
                    text="data kami terus diperbarui secara berkala untuk menghadapi ancaman siber yang berkembang pesat.",
                    img="https://img.freepik.com/free-photo/light-trails-buildings_1359-715.jpg?w=826&t=st=1706101367~exp=1706101967~hmac=2d648973d22b5e5962c40b76804e7f9b550161c8b6e95a4a453bea8610759c3d",
                ),
                dict(
                    title="Antarmuka Pengguna Intuitif",
                    text="A distant mountain chain preceded by a sea",
                    img="https://img.freepik.com/free-photo/global-business-internet-network-connection-iot-internet-things-business-intelligence-concept-busines-global-network-futuristic-technology-background-ai-generative_1258-176765.jpg?w=826&t=st=1706101393~exp=1706101993~hmac=1b6f80ffb396ddef78115805971956a5ccb8d091d49daf612a46a5ca50de4649",
                ),
            ]

            carousel(items=gambar_slide,width=1)
            left_column, right_column = st.columns(2)
            with left_column:
                st.title('Athguard')
                st.write('''Selamat datang di Athguard, perisai keamanan terpercaya untuk melindungi Anda dari tautan phishing yang berbahaya. Bersama kami, keamanan online Anda adalah prioritas utama.
                        deteksi phising berdasarkan url bukan content based.
                         Jika ingin mengirimkan saran dan kritik bisa menggunakan halaman kontak''')
                st.write('#')
                st.write('#')
                st.write('#')
                st.write('#')
                st.header('Contoh link phising')
                df = pd.read_csv('./dataset_phishing.csv')
                st.write(df)

            with right_column:
                st_lottie(animasi, height=300, key="Security")
                st.write('##')
                df1 = pd.read_csv('./webphising.csv')

                phising_sample = df1[df1['Label']=='phishing'].sample(n=10)
                phising_sample.plot(kind='bar')
                plt.title('ciri-ciri URL phising')
                plt.xlabel('URL')
                plt.xticks(rotation=45)
                st.pyplot(plt.gcf())

if selected == "Detect":
    st.title(":globe_with_meridians: Halaman Deteksi")
    RandomForest = pickle.load(open('finalized_model.h5', 'rb'))
    DecisionTree = pickle.load(open('finalized_modelDt.h5', 'rb'))
    LightBGM = pickle.load(open('finalized_modelLg.h5', 'rb'))
    df = pd.read_csv('./webphising.csv')
    vectorizer = CountVectorizer()
    url_vectorized_train = vectorizer.fit_transform(df['URL'])
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

    def tinyURL(url):
        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return 0

    def detect_ip(url):
        try:
            url_without_protocol = url.split('//')[-1].split('/')[0]
            
            ipaddress.ip_address(url_without_protocol)
            return True
        except ValueError:
            return False
    
    def extract_features(url):
        Length = len(url)
        special_mark = url.count('/') + url.count('?') + url.count('.') + url.count('@') + url.count('&') + url.count('=')
        subdomain = len(url.split('.')[0])
        HasHTTPS = True if url.startswith('https://') else False
        IsIPAddress = detect_ip(url)
        Shortened = tinyURL(url)

        features = {
            'Length': Length,
            'special_mark': special_mark,
            'subdomain' : subdomain,
            'HasHTTPS' : HasHTTPS,
            'IsIPAddress' : IsIPAddress,
            'Shortened' : Shortened    
        }

        return features
    
    Ml = st.selectbox(
            'Pilih model machine learning',
            ('Random Forest', 'Decision Tree', 'LBGM'))
    
    if(Ml=='Random Forest'):
        model = RandomForest
    
    if(Ml=='Decision Tree'):
        model = DecisionTree
    
    if(Ml=='LBGM'):
        model = LightBGM
    
    url_input = st.text_input("Masukkan URL:")

    if st.button('Check!'):
        url_vectorized = vectorizer.transform([url_input])
        url_features = extract_features(url_input)
        user_features = pd.DataFrame([url_features])
        user_features = np.array(list(url_features.values())).reshape(1, -1)
        user_features_vectorized = url_vectorized.toarray()
        combined_features = np.hstack((user_features, user_features_vectorized))
        prediction = model.predict(combined_features)
        result = prediction

        # Tampilkan hasil
        st.write(f"Hasil Deteksi: kelihatannya {result[0]}")
    
if selected == "Contacts":
        st.title(":mailbox: Kontak Kami")
        st.write('##')  
        contact_form = """
            <form action="https://formsubmit.co/yusufathagunawan@gmail.com" method="POST">
                <input type="hidden" name="_captcha" value="false">
                <input type="text" name="name" placeholder="Nama Anda" required>
                <input type="email" name="email" placeholder="Surel Anda" required>
                <textarea name="message" placeholder="Kirim Pesan Anda"></textarea>
                <button type="submit">Send</button>
            </form>
            """
        st.markdown(contact_form, unsafe_allow_html=True)
        def local_css(file_name):
                with open(file_name) as f:
                    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
                
        local_css("style/style.css")
