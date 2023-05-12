import tkinter as tk
import requests
import json
with open('config.json') as file:
        data = json.load(file)

class VTGUI:
    def __init__(self, master):
        self.master = master
        master.title("Heypers Protect URL checker")

    #    self.apikey_label = tk.Label(master, text="API key:")
    #    self.apikey_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

    #    self.apikey_entry = tk.Entry(master, width=50)
    #    self.apikey_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)

        self.url_label = tk.Label(master, text="URL to check:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)

        self.check_button = tk.Button(master, text="Check", command=self.check_url)
        self.check_button.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        self.result_label = tk.Label(master, text="")
        self.result_label.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

    def check_url(self):
        api_key = data["token"]
        url_to_check = self.url_entry.get()

        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': api_key, 'resource': url_to_check}
        response = requests.get(url, params=params)
        json_response = json.loads(response.content)

        if json_response['response_code'] == 1:
            detection_ratio = 'Обнаружили вирус: ' + str(json_response['positives']) + '/' + str(json_response['total'])
            self.result_label.configure(text=detection_ratio)
            av_results = ''
            for av, malware in json_response['scans'].items():
                if malware['detected']:
                    av_results += av + ': ' + malware['result'] + '\n'
            self.result_label.configure(text=detection_ratio + '\n' + av_results)
        else:
            self.result_label.configure(text="Предоставленная ссылка не может быть обработана")

root = tk.Tk()
gui = VTGUI(root)
root.mainloop()