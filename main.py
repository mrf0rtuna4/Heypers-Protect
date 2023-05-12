import os
import tkinter as tk
from tkinter import filedialog
import requests
import logging
import json

with open('src\config.json') as file:
        data = json.load(file)

API_KEY = data["token"]

logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def check_link(link):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': link}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        positives = response.json()['positives']
        total = response.json()['total']
        if positives > 0:
            result.config(text=f'Вредоносный веб-сайт! {positives}/{total} обнаружили вредонос.')
            logging.info(f'{link} - Malicious website')
        else:
            result.config(text='Безопасный веб-сайт.')
            logging.info(f'{link} - Safe website')
    else:
        result.config(text='Что-то пошло не так.')
        logging.error(f'Something went wrong with link {link}')

def check_file():
    file_path = filedialog.askopenfilename(title='Select a file', filetypes=(('All files', '*.*'), ))
    if file_path:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': API_KEY}
        files = {'file': ('FILENAME_HERE', open(file_path, 'rb'))}
        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            resource = response.json()['resource']
            report_url = f'https://www.virustotal.com/gui/file/{resource}/detection'
            result.config(text=f'Успешно загрузили ваш файл на проверку, проверено здесь: {report_url}')
            logging.info(f'{file_path} - Successfully uploaded to VirusTotal. Check the report at {report_url}')
        else:
            result.config(text='Something went wrong.')
            logging.error(f'Something went wrong with file {file_path}')


window = tk.Tk()

link_label = tk.Label(window, text='Введите ссылку:')
link_label.pack()

link_entry = tk.Entry(window, width=50)
link_entry.pack()

link_button = tk.Button(window, text='Проверить', command=lambda: check_link(link_entry.get()))
link_button.pack()

separator = tk.Frame(height=2, bd=1, relief='sunken')
separator.pack(fill='x', padx=5, pady=5)

file_label = tk.Label(window, text='Выберите ваш файл для проверки:')
file_label.pack()

file_button = tk.Button(window, text='Выбрать файл', command=check_file)
file_button.pack()

result = tk.Label(window, text='')
result.pack()

window.mainloop()
