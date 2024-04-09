import sys
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QComboBox
from Crypto.Cipher import AES
from hashlib import sha256

class MainWindow(QWidget):
  def __init__(self):
    super().__init__()

    self.password = ''
    self.file_to_enc = ''
    self.encrypted_file = ''

    self.init_ui()

  def init_ui(self):
    # Заголовок окна
    self.setWindowTitle('Simple Crypter v1.0 by Thoisoi Three')

    # Вертикальный layout
    main_layout = QVBoxLayout()

    # Блок выбора первого файла
    first_file_layout = QHBoxLayout()

    # Label для первого файла
    self.first_file_label = QLabel('File to process path:')
    first_file_layout.addWidget(self.first_file_label)

    # LineEdit для первого файла
    self.first_file_edit = QLineEdit()
    self.first_file_edit.setReadOnly(True)
    first_file_layout.addWidget(self.first_file_edit)

    # Кнопка выбора первого файла
    self.first_file_button = QPushButton('...')
    self.first_file_button.clicked.connect(self.select_first_file)
    first_file_layout.addWidget(self.first_file_button)

    # Блок выбора второго файла
    second_file_layout = QHBoxLayout()

    # Label для второго файла
    self.second_file_label = QLabel('Processed file path')
    second_file_layout.addWidget(self.second_file_label)

    # LineEdit для второго файла
    self.second_file_edit = QLineEdit()
    self.second_file_edit.setReadOnly(True)
    second_file_layout.addWidget(self.second_file_edit)

    # Кнопка выбора второго файла
    self.second_file_button = QPushButton('...')
    self.second_file_button.clicked.connect(self.select_second_file)
    second_file_layout.addWidget(self.second_file_button)

    # Блок выбора первого файла
    password_layout = QHBoxLayout()

    # Label для первого файла
    self.password_layout = QLabel(' ')
    first_file_layout.addWidget(self.password_layout)


    #password
    self.password_label = QLabel('Password:')
    password_layout.addWidget(self.password_label)

    # LineEdit для пароля
    self.password_edit = QLineEdit()
    self.password_edit.setEchoMode(QLineEdit.Password)
    password_layout.addWidget(self.password_edit)

    # Добавление layoutов
    main_layout.addLayout(first_file_layout)
    main_layout.addLayout(second_file_layout)
    main_layout.addLayout(password_layout)

    #working mode 
    self.mode = QComboBox()
    self.mode.addItem('Encode')
    self.mode.addItem('Decode')
    main_layout.addWidget(self.mode)

    # Кнопка "Показать пароль"
    self.show_password_button = QPushButton('Show password')
    self.show_password_button.clicked.connect(self.on_show_password_button_clicked)
    main_layout.addWidget(self.password_edit)
    main_layout.addWidget(self.show_password_button)

    #button
    self.run_button = QPushButton('Run')
    self.run_button.clicked.connect(self.run_code)
    main_layout.addWidget(self.run_button)

    # Установка layout
    self.setLayout(main_layout)

  def on_show_password_button_clicked(self):
    # Обработка нажатия кнопки
    if self.show_password_button.text() == 'Show password':
      self.password_edit.setEchoMode(QLineEdit.Normal)
      self.show_password_button.setText('Hide password')
    else:
      self.password_edit.setEchoMode(QLineEdit.Password)
      self.show_password_button.setText('Show password')

  def select_first_file(self):
    self.file_to_enc = QFileDialog.getOpenFileName(self, 'Select the file to process', '~')[0]
    self.first_file_edit.setText(self.file_to_enc)

  def select_second_file(self):
    self.encrypted_file = QFileDialog.getSaveFileName(self, 'Save the processed file', '~')[0]
    self.second_file_edit.setText(self.encrypted_file)
  def run_code(self):

    def encrypt_f(text, password):

        # Преобразуем пароль в ключ
        key = sha256(password.encode()).digest()

        # Создаем объект шифрования AES-256
        cipher = AES.new(key, AES.MODE_ECB)

        # Дополняем текст до кратной 16 байт длины с помощью PKCS#7 padding
        pad = lambda s: s + bytes([len(s) % 16] * (16 - len(s) % 16))
        padded_text = pad(text)

        # Шифруем текст
        ciphertext = cipher.encrypt(padded_text)

        return ciphertext
    def decrypt_f(ciphertext, password):

        # Преобразуем пароль в ключ
        key = sha256(password.encode()).digest()

        # Создаем объект шифрования AES-256
        cipher = AES.new(key, AES.MODE_ECB)

        # Расшифровываем текст
        plaintext = cipher.decrypt(ciphertext)

        # Удаляем нулевые байты в конце
        return plaintext.rstrip(b'\0')
    def encrypt_file(input_file, output_file, password):

        with open(input_file, "rb") as f_in:
            plaintext = f_in.read()

        ciphertext = encrypt_f(plaintext, password)

        with open(output_file, "wb") as f_out:
            f_out.write(ciphertext)
    def decrypt_file(input_file, output_file, password):

        with open(input_file, "rb") as f_in:
            ciphertext = f_in.read()

        plaintext = decrypt_f(ciphertext, password)

        with open(output_file, "wb") as f_out:
            f_out.write(plaintext)

    in_file = self.file_to_enc
    out_file = self.encrypted_file
    password = self.password



    if self.mode.currentText() == "Encode":
        encrypt_file(in_file, out_file, password)
    else:
       decrypt_file(in_file, out_file, password)

if __name__ == '__main__':
  app = QApplication(sys.argv)
  window = MainWindow()
  window.show()
  sys.exit(app.exec_())