#!/usr/bin/env python
# CY83R-3X71NC710N Copyright 2023

# Importing necessary libraries
import scapy.all as scapy
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# Create a function that will detect malicious DDoS threats
def detect_DDoS():
    # Creating a packet capture using scapy
    packets = scapy.sniff(iface="eth0", timeout=20)
    # Creating a list for the packet capture
    packet_list = []
    # Iterate through the packet capture
    for packet in packets:
        # Appending the packet capture to the list
        packet_list.append(packet)
    # Converting the list to a dataframe
    df = pd.DataFrame(packet_list)
    # Dropping unnecessary columns from the dataframe
    df.drop(["time", "len", "src", "dst", "payload"], axis=1, inplace=True)
    # Setting up the KMeans model
    model = KMeans(n_clusters=2)
    # Fitting the model to the data
    model.fit(df)
    # Predicting the labels
    labels = model.predict(df)
    # Creating a new column in the dataframe with the labels
    df["label"] = labels
    # Creating a new dataframe with the malicious packets
    malicious_df = df[df["label"] == 1]
    # Creating a new dataframe with the benign packets
    benign_df = df[df["label"] == 0]
    # Plotting the malicious packets
    plt.scatter(malicious_df["proto"], malicious_df["flags"], color="red")
    # Plotting the benign packets
    plt.scatter(benign_df["proto"], benign_df["flags"], color="blue")
    # Displaying the plot
    plt.show()

# Calling the function
detect_DDoS()
