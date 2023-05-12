import requests
import json
import hashlib
import tkinter as tk
from tkinter import filedialog

with open('config.json') as file:
        data = json.load(file)

def check_hash(api_key, file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}
    response = requests.get(url, params=params)
    json_response = json.loads(response.content)
    
    if json_response['response_code'] == 1:
        detection_ratio = 'Detection ratio: ' + str(json_response['positives']) + '/' + str(json_response['total'])
        print(detection_ratio)
        for av, malware in json_response['scans'].items():
            if malware['detected']:
                print(av + ': ' + malware['result'])
    else:
        print("The requested hash is not yet analyzed")

def browse_file():
    file_path = filedialog.askopenfilename()
    check_hash(api_key, file_path)

if __name__ == '__main__':
    api_key = data["token"]

    root = tk.Tk()
    root.withdraw()
    root.mainloop()

    browse_button = tk.Button(text="Browse", command=browse_file)
    browse_button.pack()

