import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd
import numpy as np
from scipy.stats import wasserstein_distance
from tkinter import scrolledtext
import requests
import json

def displayInfo(info):
    def fetch_data(url):
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch data: {response.status_code}"}

    def format_data(data):
        formatted = json.dumps(data, indent=4)  # Pretty print the JSON data
        return formatted

    # URL for the GET request (You can modify this with the actual URL)
    url = f'https://virusshare.com/apiv2/file?apikey=51Rt0fdxidIDSaRb9drnZH62NjGI58Gi&hash={info[11:]}'

    # Fetch and format the data
    data = fetch_data(url)
    formatted_data = format_data(data)

    # Create the main window
    root = tk.Tk()
    root.title(f'{info} in details')

    # Create a scrolled text widget
    scrolled_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=150, height=30)
    scrolled_text.grid(column=0, pady=10, padx=10)

    # Insert data into the scrolled text widget
    scrolled_text.insert(tk.INSERT, formatted_data)

def plot_row(data, index1, index2, row3_dict, title):
    # Extract the rows to be compared
    row1 = data.iloc[index1].drop(['File Name', 'Family'])
    row2 = data.iloc[index2].drop(['File Name', 'Family'])
    file_name1 = data.iloc[index1]["File Name"]
    file_name2 = data.iloc[index2]["File Name"]

    # Convert row3_dict to a Series and align with row1 and row2
    row3 = pd.Series(row3_dict)
    aligned_row3 = row1.copy()
    for op in aligned_row3.index:
        aligned_row3[op] = row3.get(op, 0)

    # Normalize the rows
    row1_normalized = row1 / row1.sum()
    row2_normalized = row2 / row2.sum()
    aligned_row3_normalized = aligned_row3 / aligned_row3.sum()

    # Create a new Tkinter window
    window = tk.Tk()
    window.title(title)

    # Create a figure for the comparison plot
    fig = Figure(figsize=(15, 8))
    ax = fig.add_subplot(111) # Only one plot

    # Positioning for side by side bars
    bar_width = 0.2
    indices = np.arange(len(row1_normalized))

    # Plotting the normalized rows side by side
    ax.bar(indices - bar_width, row1_normalized.values, bar_width, label=file_name1[:-4] + ' based on Earth Mover\'s Distance')
    ax.bar(indices, row2_normalized.values, bar_width, label=file_name2[:-4] + ' based on Hellinger Distance')
    ax.bar(indices + bar_width, aligned_row3_normalized.values, bar_width, label='Given executable')

    displayInfo(file_name1[:-4])
    displayInfo(file_name2[:-4])

    # Plot settings
    ax.set_title('Opcode Distribution Comparison (Normalized)')
    ax.set_xlabel('Opcode')
    ax.set_ylabel('Normalized Count')
    ax.set_xticks(indices)
    ax.set_xticklabels(row1_normalized.index)
    ax.tick_params(axis='x', rotation=45)
    ax.legend()

    # Add the plot to the Tkinter window and display
    canvas = FigureCanvasTkAgg(fig, master=window)
    canvas_widget = canvas.get_tk_widget()
    canvas_widget.pack()

def hellinger_distance(p, q):
    return np.sqrt(np.sum((np.sqrt(p) - np.sqrt(q)) ** 2)) / np.sqrt(2)

def earth_movers_distance(p, q):
    return wasserstein_distance(p, q)

def get_most_similar_top_5(new_row, result=None):
    data = pd.read_csv('all_data.csv')
    new_row_series = pd.Series(new_row)
    new_row_normalized = new_row_series / new_row_series.sum()

    reference_data = data[['File Name', 'Family']]

    numeric_data = data.drop(['File Name', 'Family'], axis=1)
    normalized_data = numeric_data.div(numeric_data.sum(axis=1), axis=0)

    # Calculating Hellinger distance
    hellinger_distances = normalized_data.apply(lambda row: hellinger_distance(row, new_row_normalized), axis=1)
    
    # Calculating Earth Mover's distance
    emd_distances = normalized_data.apply(lambda row: earth_movers_distance(row, new_row_normalized), axis=1)

    # Combine results
    results = pd.concat([reference_data, pd.DataFrame({'Hellinger Distance': hellinger_distances, 'EMD': emd_distances})], axis=1)
    
    top_5_hellinger = results.sort_values(by='Hellinger Distance', ascending=True).head(5)
    top_5_emd = results.sort_values(by='EMD', ascending=True).head(5)

    return top_5_hellinger, top_5_emd


def visualize_most_similar_top_5(new_row, result=None):
    data = pd.read_csv('all_data.csv')
    new_row_series = pd.Series(new_row)
    new_row_normalized = new_row_series / new_row_series.sum()

    reference_data = data[['File Name', 'Family']]

    numeric_data = data.drop(['File Name', 'Family'], axis=1)
    normalized_data = numeric_data.div(numeric_data.sum(axis=1), axis=0)

    # Calculating Hellinger distance
    hellinger_distances = normalized_data.apply(lambda row: hellinger_distance(row, new_row_normalized), axis=1)
    
    # Calculating Earth Mover's distance
    emd_distances = normalized_data.apply(lambda row: earth_movers_distance(row, new_row_normalized), axis=1)

    # Combine results
    results = pd.concat([reference_data, pd.DataFrame({'Hellinger Distance': hellinger_distances, 'EMD': emd_distances})], axis=1)
    
    top_5_hellinger = results.sort_values(by='Hellinger Distance', ascending=True).head(5)
    top_5_emd = results.sort_values(by='EMD', ascending=True).head(5)

    plot_row(data, top_5_emd.index[0], top_5_hellinger.index[0], new_row, 'Comparison of Top EMD and Hellinger Results')

    # Create a new Tkinter window
    results_window = tk.Tk()
    results_window.title("Top 5 Similarity Results")

    # Create a Text widget
    results_text = tk.Text(results_window, height=30, width=100)
    results_text.pack()

    # Formatting and inserting the results into the Text widget
    if result is not None:
        if result == 1:
            result_str = "Prediction: Malware\n"
        else:
            result_str = "Prediction: Benign\n"
    else:
        result_str = ""
    top_5_emd_str = "Top 5 Malwarse most similar by Earth Mover's Distance:\n" + str(top_5_emd[['File Name', 'Family', 'EMD']])
    top_5_hellinger_str = "\nTop 5 Malwares most similar by Hellinger Distance:\n" + str(top_5_hellinger[['File Name', 'Family', 'Hellinger Distance']])

    results_text.insert(tk.END, result_str + top_5_emd_str + top_5_hellinger_str)

    # Start the Tkinter event loop
    results_window.mainloop()

if __name__ == "__main__":
    with open('ml_input.txt', 'r') as file:
        file_content = file.read()
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
    visualize_most_similar_top_5(new_row)


    
    
