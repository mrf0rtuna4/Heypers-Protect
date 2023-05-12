import sys
import json
import PyQt5
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QFileDialog
import requests

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setGeometry(100, 100, 300, 150)
        self.setWindowTitle('File Scanner')

        self.file_path = QLabel(self)
        self.file_path.setGeometry(20, 20, 260, 20)

        select_btn = QPushButton('Выбрать файл', self)
        select_btn.setGeometry(20, 50, 120, 30)
        select_btn.clicked.connect(self.selectFile)

        scan_btn = QPushButton('Сканировать', self)
        scan_btn.setGeometry(160, 50, 120, 30)
        scan_btn.clicked.connect(self.scanFile)

    def selectFile(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Выбрать файл')
        if file_path:
            self.file_path.setText(file_path)

    def scanFile(self):
        file_path = self.file_path.text()
        if not file_path:
            return

        with open(file_path, 'rb') as f:
            file_data = f.read()

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': '#'}
        files = {'file': ('file', file_data)}

        response = requests.post(url, files=files, params=params)
        response_json = response.json()

        if 'permalink' in response_json:
            url = response_json['permalink']
        else:
            url = 'https://www.virustotal.com/gui/file/' + response_json['resource']

        print('Submitted:', file_path)
        print('Scan URL:', url)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
