import sys
import pandas as pd
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QTextEdit
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
import subprocess


class FirewallAutomationApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Automation")
        self.setGeometry(100, 100, 1000, 600)
        self.firewall_data = []  # 방화벽 데이터를 저장할 변수
        self.firewall_file = r"\firewall_list.xlsx"  # 방화벽 리스트 파일 경로
        self.init_ui()

    def init_ui(self):
        # Main container
        main_widget = QWidget()
        main_layout = QHBoxLayout()

        # Left: Firewall List or Logo
        self.left_layout = QVBoxLayout()

        # 방화벽 리스트
        self.search_label = QLabel("방화벽 검색:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("방화벽 이름 입력...")
        self.search_input.textChanged.connect(self.filter_firewall_table)

        self.firewall_table = QTableWidget()
        self.firewall_table.setColumnCount(2)
        self.firewall_table.setHorizontalHeaderLabels(["방화벽 이름", "관리 IP"])
        self.firewall_table.horizontalHeader().setStretchLastSection(True)
        self.firewall_table.verticalHeader().setVisible(False)
        self.firewall_table.setSelectionBehavior(QTableWidget.SelectRows)

        self.left_layout.addWidget(self.search_label)
        self.left_layout.addWidget(self.search_input)
        self.left_layout.addWidget(self.firewall_table)

        # 로고
        self.logo_label = QLabel()
        pixmap = QPixmap(r"G:\Microsoft VS Code\test\pa.png")
        if not pixmap.isNull():
            pixmap = pixmap.scaled(400, 300, Qt.KeepAspectRatio)
            self.logo_label.setPixmap(pixmap)
        self.left_layout.addWidget(self.logo_label)

        # Right: Input Fields and Buttons
        right_layout = QVBoxLayout()

        self.menu_label = QLabel("메뉴 선택:")
        self.menu_combo = QComboBox()
        self.menu_combo.addItems(["트래픽 로그 추출", "시스템 로그 추출"])
        self.menu_combo.currentIndexChanged.connect(self.update_ui)

        self.src_ip_label = QLabel("출발지 IP:")
        self.src_ip_input = QLineEdit()
        self.dst_ip_label = QLabel("목적지 IP:")
        self.dst_ip_input = QLineEdit()

        self.account_label = QLabel("방화벽 계정:")
        self.account_input = QLineEdit()
        self.account_input.setPlaceholderText("계정 입력")

        self.password_label = QLabel("방화벽 비밀번호:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("비밀번호 입력")

        self.severity_label = QLabel("Severity:")
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["critical", "high", "medium", "low"])

        self.run_button = QPushButton("로그 출력")
        self.run_button.clicked.connect(self.run_action)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("로그 추출 결과가 여기에 표시됩니다.")

        right_layout.addWidget(self.menu_label)
        right_layout.addWidget(self.menu_combo)
        right_layout.addWidget(self.src_ip_label)
        right_layout.addWidget(self.src_ip_input)
        right_layout.addWidget(self.dst_ip_label)
        right_layout.addWidget(self.dst_ip_input)
        right_layout.addWidget(self.account_label)
        right_layout.addWidget(self.account_input)
        right_layout.addWidget(self.password_label)
        right_layout.addWidget(self.password_input)
        right_layout.addWidget(self.severity_label)
        right_layout.addWidget(self.severity_combo)
        right_layout.addWidget(self.run_button, alignment=Qt.AlignRight)
        right_layout.addWidget(self.log_output, 1)

        main_layout.addLayout(self.left_layout, 2)
        main_layout.addLayout(right_layout, 3)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        self.update_ui(0)  # Default to traffic log UI

    def update_ui(self, index):
        if index == 0:  # Traffic Log
            self.src_ip_label.setVisible(True)
            self.src_ip_input.setVisible(True)
            self.dst_ip_label.setVisible(True)
            self.dst_ip_input.setVisible(True)
            self.search_label.setVisible(False)
            self.search_input.setVisible(False)
            self.firewall_table.setVisible(False)
            self.logo_label.setVisible(True)
            self.severity_label.setVisible(False)
            self.severity_combo.setVisible(False)
        else:  # System Log
            self.src_ip_label.setVisible(False)
            self.src_ip_input.setVisible(False)
            self.dst_ip_label.setVisible(False)
            self.dst_ip_input.setVisible(False)
            self.search_label.setVisible(True)
            self.search_input.setVisible(True)
            self.firewall_table.setVisible(True)
            self.logo_label.setVisible(False)
            self.severity_label.setVisible(True)
            self.severity_combo.setVisible(True)
            self.load_firewall_data()

    def load_firewall_data(self):
        try:
            df = pd.read_excel(self.firewall_file)
            required_columns = {"name", "management_ip"}
            if not required_columns.issubset(df.columns):
                raise ValueError("엑셀 파일에 'name' 또는 'management_ip' 열이 없습니다.")

            self.firewall_data = df[["name", "management_ip"]].to_dict(orient="records")
            self.update_firewall_table(self.firewall_data)
        except FileNotFoundError:
            self.log_output.append(f"엑셀 파일을 찾을 수 없습니다: {self.firewall_file}")
        except Exception as e:
            self.log_output.append(f"방화벽 데이터를 불러오는 중 오류 발생: {e}")

    def update_firewall_table(self, data):
        self.firewall_table.setRowCount(len(data))
        for row, fw in enumerate(data):
            self.firewall_table.setItem(row, 0, QTableWidgetItem(fw["name"]))
            self.firewall_table.setItem(row, 1, QTableWidgetItem(fw["management_ip"]))

    def filter_firewall_table(self, text):
        filtered_data = [fw for fw in self.firewall_data if text.lower() in fw["name"].lower()]
        self.update_firewall_table(filtered_data)

    def run_action(self):
        current_menu = self.menu_combo.currentText()
        account = self.account_input.text()
        password = self.password_input.text()

        if current_menu == "트래픽 로그 추출":
            src_ip = self.src_ip_input.text()
            dst_ip = self.dst_ip_input.text()

            # 경로 추적 실행
            self.log_output.append(f"경로 추적 실행: 출발지 IP={src_ip}, 목적지 IP={dst_ip}")
            try:
                subprocess.run(["python", "firewall_ip_check_new.py", src_ip, dst_ip], check=True)
                self.log_output.append("경로 추적 완료!")
            except subprocess.CalledProcessError as e:
                self.log_output.append(f"경로 추적 중 오류 발생: {e}")

            # 트래픽 로그 추출 실행
            self.log_output.append("트래픽 로그 추출 실행 중...")
            try:
                subprocess.run(["python", "paloalto_firewall_log_new.py", src_ip, dst_ip, account, password], check=True)
                self.log_output.append("트래픽 로그 추출 완료!")
            except subprocess.CalledProcessError as e:
                self.log_output.append(f"트래픽 로그 추출 중 오류 발생: {e}")

        elif current_menu == "시스템 로그 추출":
            selected_row = self.firewall_table.currentRow()
            if selected_row != -1:
                firewall_ip = self.firewall_table.item(selected_row, 1).text()
                severity = self.severity_combo.currentText()

                self.log_output.append(f"시스템 로그 추출 실행: 방화벽 IP={firewall_ip}, Severity={severity}")
                try:
                    subprocess.run(["python", "paloalto_system_log_new.py", firewall_ip, severity, account, password], check=True)
                    self.log_output.append("시스템 로그 추출 완료!")
                except subprocess.CalledProcessError as e:
                    self.log_output.append(f"시스템 로그 추출 중 오류 발생: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FirewallAutomationApp()
    window.show()
    sys.exit(app.exec())
