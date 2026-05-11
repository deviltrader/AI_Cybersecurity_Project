import streamlit as st
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder

st.title("AI Cybersecurity Threat Detection")
st.success("🟢 AI Threat Monitoring System Active")
st.subheader("Real-Time Threat Analysis")

# Load trained model
model = pickle.load(open("model.pkl", "rb"))

# Column names
columns = [
    "duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell",
    "su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label"
]

uploaded_file = st.file_uploader("Upload Log CSV")

if uploaded_file:

    # Read uploaded dataset
    data = pd.read_csv(uploaded_file, names=columns)

    st.write("Uploaded Logs")
    st.dataframe(data.head())

    # Encode categorical columns
    for col in data.select_dtypes(include=['object']).columns:
        data[col] = LabelEncoder().fit_transform(data[col])

    # Remove label column
    X = data.drop("label", axis=1)

    # Prediction
    prediction = model.predict(X)

    st.subheader("Threat Detection Results")

    for p in prediction[:20]:

        if p == 0:
            st.success("✅ Normal Traffic")
        else:
            st.error("⚠️ Malicious Traffic Detected")