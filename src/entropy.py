import sys 
import math
from math import log
import numpy as np
import matplotlib.pyplot as plt

def compute_entropy(binary):
    
    byteArr = list(binary)
    fileSize = len(byteArr) 

    #Calculate the frequency for each byte
    freq = [] 
    for i in range(256): 
        counter = 0 
        for byte in byteArr: 
            if byte == i: 
                counter += 1 
        freq.append(float(counter) / fileSize) 

    #Compute Shannon entropy
    ent = 0.0 
    for f in freq: 
        if f > 0: 
            ent = ent + f * log(f, 2) 
    ent = -ent
   
    return ent, freq

# Print the histogram

def plot_entropy(freq):
    
    N = len(freq)

    ind = np.arange(N)  # the x locations for the groups

    fig = plt.figure(figsize=(11,5),dpi=100)
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind, freq, 1.00)
    ax.set_autoscalex_on(False)
    ax.set_xlim([0,255])

    ax.set_ylabel('Frequency')
    ax.set_xlabel('Byte')

    plt.savefig("plot/entropy.png")