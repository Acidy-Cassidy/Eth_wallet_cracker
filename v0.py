import sys
import time
import json
import secrets
import requests
from multiprocessing import Value, freeze_support
from web3 import Web3
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import psutil

# Load data from endpoints
data = {
    "MAIN": {
        "GAS_API": "https://ethgasstation.info/api/ethgasAPI.json?",
        "RPC_NODE": "https://cloudflare-eth.com/",
        "BACKUP_NODE": "https://main-light.eth.linkpool.io/",
        "CHECK_NODE": "https://eth.getblock.io/3ba2aba2-aed3-4b22-bc1d-b9a8f12fd8f7/mainnet/",
        "CHECK_SECONDARY": "https://mainnet.infura.io/v3/3011bc8a35d94c40a95e00fd63898802",
        "CHECK_POLYGON": "https://polygon-rpc.com",
        "CHECK_BSC": "https://bsc.publicnode.com/"
    },
    "VERSION": "2.0"
}

starttime = datetime.now()

def get_uptime():
    return datetime.now() - starttime

def load_web3(nodes):
    for node in nodes:
        print(f"Connecting to node: {node}")  # Debugging info
        w3 = Web3(Web3.HTTPProvider(node))
        if w3.is_connected():
            print("Connected to Web3")
            return w3
    return None

def check_balance(w3, address):
    for _ in range(5):  # Retry logic with exponential backoff
        try:
            return w3.eth.get_balance(address)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Too Many Requests
                print("Rate limited, retrying...")
                time.sleep(2 ** _)
            else:
                raise e

class MinerThread(QThread):
    update_signal = pyqtSignal(str)
    update_stats_signal = pyqtSignal(str)
    update_hits_signal = pyqtSignal(str)

    def __init__(self, miner_address, parent=None):
        super(MinerThread, self).__init__(parent)
        self.miner_address = miner_address
        self.hits = Value('i', 0)
        self.bad_hits = Value('i', 0)
        self.amount_trigger = Value('i', 200000)
        self.running = True
        self.verbose = True
        self.sleep_time = 0.01  # Default sleep time

    def run(self):
        nodes = [
            "https://cloudflare-eth.com/",
            "https://main-light.eth.linkpool.io/",
            "https://eth.getblock.io/3ba2aba2-aed3-4b22-bc1d-b9a8f12fd8f7/mainnet/",
            "https://mainnet.infura.io/v3/3011bc8a35d94c40a95e00fd63898802",
            "https://ethereumnodes.com",
            "https://nodes.mewapi.io/rpc/eth",
            "https://mainnet-nethermind.blockscout.com",
            "https://rpc.flashbots.net",
        ]
        self.update_signal.emit("Starting mining process...")
        w3 = load_web3(nodes)
        if not w3:
            self.update_signal.emit("Web3 connection failed.")
            return

        self.update_signal.emit("Mining process started.")
        while self.running:
            try:
                private_key = "0x" + secrets.token_hex(32)
                if self.verbose:
                    self.update_signal.emit(f"Generated private key: {private_key}")

                account = w3.eth.account.from_key(private_key)
                if self.verbose:
                    self.update_signal.emit(f"Generated account address: {account.address}")

                balance = check_balance(w3, account.address)
                if self.verbose:
                    self.update_signal.emit(f"Checked balance: {balance}")

                if balance > 0:
                    self.hits.value += 1
                    eth_balance = w3.from_wei(balance, 'ether')  # Correct usage of from_wei
                    self.update_signal.emit(f"[HIT] Private Key: {private_key}, Balance: {eth_balance} ETH")
                    self.update_hits_signal.emit(f"Private Key: {private_key}, Balance: {eth_balance} ETH")
                    with open("hits.txt", "a") as f:
                        f.write(f"Private Key: {private_key}, Balance: {eth_balance} ETH\n")
                else:
                    self.bad_hits.value += 1
                    eth_balance = w3.from_wei(balance, 'ether')  # Correct usage of from_wei
                    if self.verbose:
                        self.update_signal.emit(f"[MISS] Private Key: {private_key}, Balance: {eth_balance} ETH")

                # Update stats periodically
                if self.hits.value % 10 == 0 or self.bad_hits.value % 100 == 0:
                    self.update_stats_signal.emit(f"Hits: {self.hits.value}, Misses: {self.bad_hits.value}, Uptime: {get_uptime()}")
            except Exception as e:
                self.update_signal.emit(f"Failed to check balance: {e}")

            time.sleep(self.sleep_time)  # Use the dynamic sleep time

    def stop(self):
        self.running = False
        self.update_signal.emit("Mining process stopped.")

    def set_verbose(self, verbose):
        self.verbose = verbose

    def set_speed(self, sleep_time):
        self.sleep_time = sleep_time
        self.update_signal.emit(f"Speed set to: {1/self.sleep_time}x")

class SystemResourceGraph(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig, self.ax = plt.subplots(figsize=(width, height), dpi=dpi)
        super(SystemResourceGraph, self).__init__(self.fig)
        self.setParent(parent)
        self.cpu_data = []
        self.net_data = []
        self.previous_net_io = psutil.net_io_counters()
        self.update_graph()

    def update_graph(self):
        self.cpu_data.append(psutil.cpu_percent())
        current_net_io = psutil.net_io_counters()
        bytes_sent = current_net_io.bytes_sent - self.previous_net_io.bytes_sent
        bytes_recv = current_net_io.bytes_recv - self.previous_net_io.bytes_recv
        self.net_data.append(bytes_sent + bytes_recv)
        self.previous_net_io = current_net_io

        if len(self.cpu_data) > 50:
            self.cpu_data.pop(0)
            self.net_data.pop(0)

        self.ax.clear()
        self.ax.plot(self.cpu_data, label='CPU Usage (%)')
        self.ax.plot(self.net_data, label='Network Usage (Bytes)')
        self.ax.set_ylim(0, max(100, max(self.net_data)))
        self.ax.legend(loc='upper right')
        self.ax.set_title('System Resource Usage')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Usage')
        self.draw()

class MinerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.miner_thread = None
        self.resource_timer = QTimer()
        self.resource_timer.timeout.connect(self.update_resource_graph)

    def init_ui(self):
        self.setWindowTitle("ETH Miner")
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.label = QLabel("Enter your ETH address:")
        self.layout.addWidget(self.label)

        self.address_input = QLineEdit(self)
        self.layout.addWidget(self.address_input)

        button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Mining", self)
        self.start_button.clicked.connect(self.start_mining)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Mining", self)
        self.stop_button.clicked.connect(self.stop_mining)
        button_layout.addWidget(self.stop_button)

        self.verbose_button = QPushButton("Show Verbose Output", self)
        self.verbose_button.clicked.connect(self.show_verbose_output)
        button_layout.addWidget(self.verbose_button)

        self.stats_button = QPushButton("Show Stats Only", self)
        self.stats_button.clicked.connect(self.show_stats_only)
        button_layout.addWidget(self.stats_button)

        self.layout.addLayout(button_layout)

        speed_button_layout = QHBoxLayout()

        self.speed_1x_button = QPushButton("Speed 1x", self)
        self.speed_1x_button.clicked.connect(lambda: self.set_speed(0.01))
        speed_button_layout.addWidget(self.speed_1x_button)

        self.speed_2x_button = QPushButton("Speed 2x", self)
        self.speed_2x_button.clicked.connect(lambda: self.set_speed(0.005))
        speed_button_layout.addWidget(self.speed_2x_button)

        self.speed_3x_button = QPushButton("Speed 3x", self)
        self.speed_3x_button.clicked.connect(lambda: self.set_speed(0.001))
        speed_button_layout.addWidget(self.speed_3x_button)

        self.layout.addLayout(speed_button_layout)

        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)
        self.layout.addWidget(self.output_text)

        self.hits_text = QTextEdit(self)
        self.hits_text.setReadOnly(True)
        self.layout.addWidget(self.hits_text)

        self.resource_graph = SystemResourceGraph(self, width=8, height=4, dpi=100)
        self.layout.addWidget(self.resource_graph)

    def start_mining(self):
        miner_address = self.address_input.text()
        print(f"Starting mining with address: {miner_address}")  # Debugging info
        if len(miner_address) != 42:
            self.output_text.append("Invalid Ethereum address.")
            return

        self.miner_thread = MinerThread(miner_address)
        self.miner_thread.update_signal.connect(self.update_output)
        self.miner_thread.update_stats_signal.connect(self.update_output)
        self.miner_thread.update_hits_signal.connect(self.update_hits)
        self.miner_thread.start()
        self.resource_timer.start(1000)

    def stop_mining(self):
        if self.miner_thread:
            self.miner_thread.stop()
            self.miner_thread.wait()
        self.resource_timer.stop()

    def show_verbose_output(self):
        if self.miner_thread:
            self.miner_thread.set_verbose(True)

    def show_stats_only(self):
        if self.miner_thread:
            self.miner_thread.set_verbose(False)

    def set_speed(self, sleep_time):
        if self.miner_thread:
            self.miner_thread.set_speed(sleep_time)

    def update_output(self, message):
        self.output_text.append(message)
        self.output_text.ensureCursorVisible()  # Scroll to the latest message

    def update_hits(self, message):
        self.hits_text.append(message)
        self.hits_text.ensureCursorVisible()  # Scroll to the latest message

    def update_resource_graph(self):
        self.resource_graph.update_graph()

if __name__ == "__main__":
    freeze_support()
    app = QApplication(sys.argv)
    miner_app = MinerApp()
    miner_app.show()
    sys.exit(app.exec_())
