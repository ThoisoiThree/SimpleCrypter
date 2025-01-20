import sys
from PyQt5.QtWidgets import QApplication, QWidget, QFileDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QComboBox
from PyQt5.QtGui import QClipboard
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256
from Crypto.Random import get_random_bytes

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.password = ''
        self.file_to_enc = ''
        self.encrypted_file = ''

        # RSA Keys
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

        self.init_ui()

    def init_ui(self):
        # Заголовок окна
        self.setWindowTitle('Simple Crypter v2.0 by Thoisoi Three')

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
        self.second_file_label = QLabel('Processed file path:')
        second_file_layout.addWidget(self.second_file_label)

        # LineEdit для второго файла
        self.second_file_edit = QLineEdit()
        self.second_file_edit.setReadOnly(True)
        second_file_layout.addWidget(self.second_file_edit)

        # Кнопка выбора второго файла
        self.second_file_button = QPushButton('...')
        self.second_file_button.clicked.connect(self.select_second_file)
        second_file_layout.addWidget(self.second_file_button)

        # Блок выбора пароля
        password_layout = QHBoxLayout()

        # Label для пароля
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

        # Working mode
        self.mode = QComboBox()
        self.mode.addItem('Encode')
        self.mode.addItem('Decode')
        main_layout.addWidget(self.mode)

        # Encryption scheme selection
        self.scheme = QComboBox()
        self.scheme.addItem('AES-256')
        self.scheme.addItem('Hybrid RSA-AES')
        self.scheme.currentIndexChanged.connect(self.toggle_key_fields)
        main_layout.addWidget(self.scheme)

        # Public Key Field
        public_key_layout = QHBoxLayout()
        self.public_key_label = QLabel('Public key')
        self.public_key_label.setVisible(False)
        public_key_layout.addWidget(self.public_key_label)

        self.public_key_field = QLineEdit()
        self.public_key_field.setReadOnly(True)
        self.public_key_field.setText(self.public_key.export_key().decode())
        self.public_key_field.setVisible(False)
        public_key_layout.addWidget(self.public_key_field)

        self.copy_public_key_button = QPushButton('Copy')
        self.copy_public_key_button.clicked.connect(self.copy_public_key)
        self.copy_public_key_button.setVisible(False)
        public_key_layout.addWidget(self.copy_public_key_button)
        main_layout.addLayout(public_key_layout)

        # Private Key Field
        private_key_layout = QHBoxLayout()
        self.private_key_label = QLabel('Private key')
        self.private_key_label.setVisible(False)
        private_key_layout.addWidget(self.private_key_label)

        self.private_key_field = QLineEdit()
        self.private_key_field.setReadOnly(True)
        self.private_key_field.setText(self.private_key.export_key().decode())
        self.private_key_field.setVisible(False)
        private_key_layout.addWidget(self.private_key_field)

        self.copy_private_key_button = QPushButton('Copy')
        self.copy_private_key_button.clicked.connect(self.copy_private_key)
        self.copy_private_key_button.setVisible(False)
        private_key_layout.addWidget(self.copy_private_key_button)
        main_layout.addLayout(private_key_layout)

        # Save Keys Button
        self.save_keys_button = QPushButton('Save Keys')
        self.save_keys_button.clicked.connect(self.save_keys)
        self.save_keys_button.setVisible(False)
        main_layout.addWidget(self.save_keys_button)

        # Кнопка "Показать пароль"
        self.show_password_button = QPushButton('Show password')
        self.show_password_button.clicked.connect(self.on_show_password_button_clicked)
        main_layout.addWidget(self.password_edit)
        main_layout.addWidget(self.show_password_button)

        # Run button
        self.run_button = QPushButton('Run')
        self.run_button.clicked.connect(self.run_code)
        main_layout.addWidget(self.run_button)

        # Установка layout
        self.setLayout(main_layout)

    def toggle_key_fields(self):
        is_hybrid = self.scheme.currentText() == 'Hybrid RSA-AES'
        self.public_key_label.setVisible(is_hybrid)
        self.public_key_field.setVisible(is_hybrid)
        self.copy_public_key_button.setVisible(is_hybrid)
        self.private_key_label.setVisible(is_hybrid)
        self.private_key_field.setVisible(is_hybrid)
        self.copy_private_key_button.setVisible(is_hybrid)
        self.save_keys_button.setVisible(is_hybrid)

    def copy_public_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.public_key_field.text())

    def copy_private_key(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.private_key_field.text())

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

    def aes_encrypt(self, plaintext, password):
        key = sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce, ciphertext, tag

    def aes_decrypt(self, nonce, ciphertext, tag, password):
        key = sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def hybrid_encrypt(self, plaintext):
        aes_key = get_random_bytes(32)  # 256 бит
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        nonce = cipher_aes.nonce
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
        return encrypted_aes_key, nonce, ciphertext, tag

    def hybrid_decrypt(self, encrypted_aes_key, nonce, ciphertext, tag):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def save_keys(self):
        save_path = QFileDialog.getExistingDirectory(self, 'Select Directory to Save Keys')
        if save_path:
            with open(f'{save_path}/public_key.pem', 'w') as pub_file:
                pub_file.write(self.public_key.export_key().decode())
            with open(f'{save_path}/private_key.pem', 'w') as priv_file:
                priv_file.write(self.private_key.export_key().decode())

    def run_code(self):
        in_file = self.file_to_enc
        out_file = self.encrypted_file
        password = self.password_edit.text()

        if not in_file or not out_file or not password:
            return

        with open(in_file, 'rb') as f:
            plaintext = f.read()

        if self.mode.currentText() == "Encode":
            if self.scheme.currentText() == 'AES-256':
                nonce, ciphertext, tag = self.aes_encrypt(plaintext, password)
                with open(out_file, 'wb') as f:
                    f.write(nonce + tag + ciphertext)
            elif self.scheme.currentText() == 'Hybrid RSA-AES':
                encrypted_aes_key, nonce, ciphertext, tag = self.hybrid_encrypt(plaintext)
                with open(out_file, 'wb') as f:
                    f.write(encrypted_aes_key + nonce + tag + ciphertext)
        else:
            with open(in_file, 'rb') as f:
                data = f.read()

            if self.scheme.currentText() == 'AES-256':
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
                plaintext = self.aes_decrypt(nonce, ciphertext, tag, password)
            elif self.scheme.currentText() == 'Hybrid RSA-AES':
                encrypted_aes_key, nonce, tag, ciphertext = data[:256], data[256:272], data[272:288], data[288:]
                plaintext = self.hybrid_decrypt(encrypted_aes_key, nonce, ciphertext, tag)

            with open(out_file, 'wb') as f:
                f.write(plaintext)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())