"""
Author: Adrien RICQUE
Version: 2.2
Creation Date: 23/07/2024

Update Date: 29/07/2024
Actor: Adrien RICQUE
"""

import sys
from re import match
from PyQt6.QtWidgets import (
    QMainWindow, QApplication,
    QLabel, QToolBar, QStatusBar, QLineEdit, QVBoxLayout, QWidget, QDialogButtonBox
)
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QDialog

from report_pdf import generate_detail_cve_report
from techo_checker import check_google_chrome_cve, check_jira_cve, check_eset_cve

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("My App")
        width = 500
        height = 200
        self.setFixedSize(width,height)

        label = QLabel("Hello!")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.setCentralWidget(label)

        toolbar = QToolBar("My main toolbar")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        button_action = QAction(QIcon("icons/home.png"), "Home", self)
        button_action.setStatusTip("Go back to Home page")
        button_action.triggered.connect(self.show_homepage)
        button_action.setCheckable(True)
        toolbar.addAction(button_action)

        toolbar.addSeparator()

        self.setStatusBar(QStatusBar(self))

    def show_homepage(self, checked):
        self.w = HomePage()
        self.w.show()
        self.close()

    def onMyToolBarButtonClick(self, s):
        print("click", s)

# -----------------------------------------------------------------------

class HomePage(MainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Home Page")

        # Boutton pour accéder au cve checker
        self.cvecheckButton = QPushButton("CVE Checker")
        self.cvecheckButton.clicked.connect(self.show_cve_checker_page)       

        # Boutton de check de text 
        self.reportButton = QPushButton("Generate a detail report")
        self.reportButton.clicked.connect(self.show_pdfreport_page)

        # Import des éléments dans la page
        layout = QVBoxLayout()
        layout.addWidget(self.cvecheckButton)
        layout.addWidget(self.reportButton)

        container = QWidget()
        container.setLayout(layout)

        # Set the central widget of the Window.
        self.setCentralWidget(container)

    def show_cve_checker_page(self, checked):
        self.w = CveChecker()
        self.w.show()
        self.close()

    def show_pdfreport_page(self, checked):
        self.w = ReportPDFWindow()
        self.w.show()
        self.close()

# ---------------------------------------------------------------------------

class CveChecker(MainWindow):
    """
    L'objectif de cette classe est de regrouper les fonctionnalités liés 
    à la vérification de cve critiques sur les 3 technologies courantes :
    Google Chrome, Jira et Esset Antivirus
    """
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Home Page")

        # Boutton pour google chrome
        self.googleButton = QPushButton("Google Chrome")
        self.googleButton.clicked.connect(check_google_chrome_cve)    

        # Boutton pour jira
        self.jiraButton = QPushButton("Jira")
        self.jiraButton.clicked.connect(check_jira_cve)

        # Boutton pour eset antivirus
        self.esetButton = QPushButton("Eset Antivirus")
        self.esetButton.clicked.connect(check_eset_cve)  

        # Import des éléments dans la page
        layout = QVBoxLayout()
        layout.addWidget(self.googleButton)
        layout.addWidget(self.jiraButton)
        layout.addWidget(self.esetButton)

        container = QWidget()
        container.setLayout(layout)

        # Set the central widget of the Window.
        self.setCentralWidget(container)

# ---------------------------------------------------------------------------

class ReportPDFWindow(MainWindow):
    def __init__(self):
        super().__init__()
        self.login = ""
        # Zone de text pour entrer la CVE
        self.input_cve = QLineEdit()
        self.input_cve.setPlaceholderText("CVE Details Report")

        # Zone de text pour entrer son login
        self.input_login = QLineEdit()
        self.input_login.setPlaceholderText("Email")

        # Zone de text pour entrer son mot de pass
        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_password.setPlaceholderText("Password")     

        # Boutton de check de text 
        self.pushButton = QPushButton("Generate")
        self.pushButton.clicked.connect(self.use_it)

        # Import des éléments à la page
        layout = QVBoxLayout()
        layout.addWidget(self.input_cve)
        layout.addWidget(self.input_login)
        layout.addWidget(self.input_password)
        layout.addWidget(self.pushButton)

        container = QWidget()
        container.setLayout(layout)

        # Set the central widget of the Window.
        self.setCentralWidget(container)

    def use_it(self):
        """ Cette fonction permet de récupérer les crédentials 
            ainsi que la cve voulu pour utiliser la fonction de
            génération d'un rapport détaillé dans le fichier report_pdf.py
        """
        username = self.input_login.text()
        self.verification_login = self.verify_login(username)
        if self.verification_login is True :
            password = self.input_password.text()
            cve = self.input_cve.text()
            self.verificationcve = self.verify_cve_format(cve)
            if self.verificationcve is True:
                generate_detail_cve_report(username, password, cve)

    def verify_login(self, login):
        if login == "":
            self.w = ErrorLoginEmpty()
            self.w.show()
            return False
        else :
            return True

    def verify_cve_format(self, cve):
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        if match(cve_pattern, cve):
            print(f"String matches pattern: {cve_pattern}")
            return True
        else :
            self.w = ErrorCveFormatAlerte()
            self.w.show()
            return False
        
# ---------------------------------------------------------
class ErrorCveFormatAlerte(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Error Cve Format Alerte")

        QBtn = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        self.layout = QVBoxLayout()
        message = QLabel("The format of the cve is not correct !")
        self.layout.addWidget(message)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)

# ---------------------------------------------------------------------------
class ErrorLoginEmpty(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Error Login Empty")

        QBtn = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        self.layout = QVBoxLayout()
        message = QLabel("You need to use an opencve account !")
        self.layout.addWidget(message)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)

# ---------------------------------------------------------------------------

app = QApplication(sys.argv)
w = HomePage()
w.show()
app.exec()

