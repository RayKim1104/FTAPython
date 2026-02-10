import socket
import threading
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import time
import json
from datetime import datetime
import urllib.request
try:
    import miniupnpc
except ImportError:
    miniupnpc = None

# Constants
BROADCAST_PORT = 50001
TRANSFER_PORT = 50002
BUFFER_SIZE = 4096
TIMEOUT = 5
RECEIVED_DIR = "Received"

class P2PFileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Share (Python) - External Network Support")
        self.root.geometry("750x700")

        # Ensure Received directory exists
        if not os.path.exists(RECEIVED_DIR):
            os.makedirs(RECEIVED_DIR)

        self.peers = {} # {ip: last_seen_time}
        self.my_ip = self.get_my_ip()
        self.public_ip = "불러오는 중..."
        self.selected_file_path = ""
        self.upnp_status = "확인 중..."
        self.status_var = tk.StringVar(value="대기 중...")
        
        # Cancellation control
        self.cancel_event = threading.Event()
        self.transfer_socket = None

        self.setup_ui()
        
        # Start discovery threads
        self.stop_threads = threading.Event()
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        threading.Thread(target=self.receive_server, daemon=True).start()
        threading.Thread(target=self.fetch_public_ip, daemon=True).start()
        threading.Thread(target=self.apply_upnp, daemon=True).start()
        
        # Periodic UI update
        self.update_peer_list_ui()
        self.log(f"애플리케이션 시작됨. 내 로컬 IP: {self.my_ip}")

    def get_my_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def fetch_public_ip(self):
        try:
            self.public_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
            self.root.after(0, lambda: self.ip_label.config(text=f"내 로컬 IP: {self.my_ip} | 공인 IP: {self.public_ip}"))
            self.log(f"공인 IP 확인됨: {self.public_ip}")
        except Exception as e:
            self.public_ip = "확인 실패"
            self.log(f"공인 IP 확인 실패: {e}")

    def apply_upnp(self):
        if not miniupnpc:
            self.upnp_status = "miniupnpc 라이브러리 없음"
            self.root.after(0, lambda: self.upnp_label.config(text=f"UPnP: {self.upnp_status}", fg="red"))
            self.log("UPnP 라이브러리가 설치되지 않았습니다 (pip install miniupnpc)")
            return

        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            devices = upnp.discover()
            if devices > 0:
                upnp.selectigd()
                # Remove existing mapping if any
                upnp.deleteportmapping(TRANSFER_PORT, 'TCP')
                # Add new mapping
                res = upnp.addportmapping(TRANSFER_PORT, 'TCP', self.my_ip, TRANSFER_PORT, 'P2P File Transfer', '')
                if res:
                    self.upnp_status = "성공 (외부 접속 가능)"
                    self.root.after(0, lambda: self.upnp_label.config(text=f"UPnP: {self.upnp_status}", fg="green"))
                    self.log(f"UPnP 포트 매핑 성공: {TRANSFER_PORT} -> {self.my_ip}")
                else:
                    self.upnp_status = "실패 (공유기 거부)"
                    self.root.after(0, lambda: self.upnp_label.config(text=f"UPnP: {self.upnp_status}", fg="orange"))
            else:
                self.upnp_status = "실패 (UPnP 장치 없음)"
                self.root.after(0, lambda: self.upnp_label.config(text=f"UPnP: {self.upnp_status}", fg="red"))
                self.log("네트워크에서 UPnP 장치를 찾을 수 없습니다.")
        except Exception as e:
            self.upnp_status = f"오류: {e}"
            self.root.after(0, lambda: self.upnp_label.config(text=f"UPnP: {self.upnp_status}", fg="red"))
            self.log(f"UPnP 설정 중 오류 발생: {e}")

    def log(self, message):
        timestamp = datetime.now().strftime("[%H:%M:%S] ")
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, timestamp + message + "\n")
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

    def format_size(self, size_bytes):
        # 1GB = 1024 * 1024 * 1024 bytes
        if size_bytes >= 1073741824:
            return f"{size_bytes / 1073741824:.2f} GB"
        else:
            return f"{size_bytes / 1048576:.2f} MB"

    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, pady=10)
        header.pack(fill=tk.X)
        self.ip_label = tk.Label(header, text=f"내 로컬 IP: {self.my_ip} | 공인 IP: {self.public_ip}", font=("Arial", 11, "bold"))
        self.ip_label.pack()
        
        self.upnp_label = tk.Label(header, text=f"UPnP: {self.upnp_status}", font=("Arial", 9))
        self.upnp_label.pack()

        # Peer List
        list_frame = tk.LabelFrame(self.root, text="온라인 피어 (자동 감지)", padx=10, pady=10, height=180)
        list_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        list_frame.pack_propagate(False)
        
        self.peer_listbox = tk.Listbox(list_frame)
        self.peer_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.peer_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.peer_listbox.yview)

        # Scan Button
        tk.Button(list_frame, text="새로고침 스캔", command=self.manual_scan).pack(side=tk.BOTTOM, pady=5)

        # Manual IP input
        manual_frame = tk.Frame(self.root, padx=10, pady=5)
        manual_frame.pack(fill=tk.X)
        tk.Label(manual_frame, text="전송할 대상 IP:").pack(side=tk.LEFT)
        self.manual_ip_entry = tk.Entry(manual_frame)
        self.manual_ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # File Selection & Send
        file_frame = tk.LabelFrame(self.root, text="파일 제어", padx=10, pady=10)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_label = tk.Label(file_frame, text="선택된 파일 없음", anchor=tk.W, fg="blue")
        self.file_label.pack(fill=tk.X, pady=5)
        
        btn_frame = tk.Frame(file_frame)
        btn_frame.pack(fill=tk.X)
        
        tk.Button(btn_frame, text="파일 선택", command=self.select_file, bg="#2196F3", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        self.send_btn = tk.Button(btn_frame, text="보내기", command=self.send_file_flow, bg="#4CAF50", fg="white", width=15, state=tk.DISABLED)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="받은 폴더 열기", command=self.open_received_folder, bg="#FF9800", fg="white", width=15).pack(side=tk.LEFT, padx=5)

        # Progress Bar & Cancel
        progress_frame = tk.Frame(self.root, padx=10, pady=5)
        progress_frame.pack(fill=tk.X)
        
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.cancel_btn = tk.Button(progress_frame, text="취소", command=self.cancel_transfer, bg="#F44336", fg="white", state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        # Console Log
        console_frame = tk.LabelFrame(self.root, text="로그", padx=10, pady=10)
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.console = tk.Text(console_frame, height=10, state=tk.DISABLED, bg="#f0f0f0")
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        c_scrollbar = tk.Scrollbar(console_frame)
        c_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.config(yscrollcommand=c_scrollbar.set)
        c_scrollbar.config(command=self.console.yview)

        # Status
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def manual_scan(self):
        self.peers.clear()
        self.peer_listbox.delete(0, tk.END)
        self.log("피어 리스트를 초기화하고 다시 스캔합니다...")

    def open_received_folder(self):
        if os.path.exists(RECEIVED_DIR):
            os.startfile(RECEIVED_DIR)
        else:
            self.log("받은 파일 폴더가 아직 생성되지 않았습니다.")

    def cancel_transfer(self):
        if messagebox.askyesno("취소", "전송을 취소하시겠습니까?"):
            self.cancel_event.set()
            if self.transfer_socket:
                try:
                    self.transfer_socket.close()
                except:
                    pass
            self.log("사용자에 의해 전송이 취소되었습니다.")
            self.status_var.set("취소됨")

    def update_peer_list_ui(self):
        if self.stop_threads.is_set():
            return
            
        current_time = time.time()
        active_peers = [ip for ip, last_seen in self.peers.items() if current_time - last_seen < 10]
        
        selected = self.peer_listbox.curselection()
        current_val = self.peer_listbox.get(selected[0]) if selected else None

        self.peer_listbox.delete(0, tk.END)
        for ip in active_peers:
            self.peer_listbox.insert(tk.END, ip)
            if ip == current_val:
                self.peer_listbox.selection_set(tk.END)
            
        self.root.after(2000, self.update_peer_list_ui)

    def broadcast_presence(self):
        broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while not self.stop_threads.is_set():
            msg = json.dumps({"type": "HELLO", "ip": self.my_ip}).encode('utf-8')
            broadcast_sock.sendto(msg, ('<broadcast>', BROADCAST_PORT))
            time.sleep(3)

    def listen_for_peers(self):
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.bind(('', BROADCAST_PORT))
        listen_sock.settimeout(1.0)
        
        while not self.stop_threads.is_set():
            try:
                data, addr = listen_sock.recvfrom(1024)
                msg = json.loads(data.decode('utf-8'))
                if msg.get("type") == "HELLO" and msg.get("ip") != self.my_ip:
                    if msg["ip"] not in self.peers:
                        self.log(f"새 피어 발견: {msg['ip']}")
                    self.peers[msg["ip"]] = time.time()
            except socket.timeout:
                continue
            except Exception:
                continue

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            self.file_label.config(text=f"선택된 파일: {filename}", fg="green")
            self.send_btn.config(state=tk.NORMAL)
            self.log(f"파일 선택됨: {filename}")

    def send_file_flow(self):
        selected_index = self.peer_listbox.curselection()
        target_ip = ""
        if selected_index:
            target_ip = self.peer_listbox.get(selected_index)
        else:
            target_ip = self.manual_ip_entry.get().strip()
            
        if not target_ip:
            messagebox.showwarning("경고", "파일을 보낼 대상을 선택하거나 IP를 입력하세요.")
            return

        if not self.selected_file_path:
            messagebox.showwarning("경고", "보낼 파일을 먼저 선택하세요.")
            return

        threading.Thread(target=self.send_file, args=(target_ip, self.selected_file_path), daemon=True).start()

    def send_file(self, ip, file_path):
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        
        self.log(f"전송 시도 -> {ip} ({filename})")
        self.status_var.set(f"연결 중: {ip}")
        
        self.cancel_event.clear()
        self.root.after(0, lambda: self.cancel_btn.config(state=tk.NORMAL))
        
        try:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.transfer_socket = client_sock
            
            client_sock.settimeout(15)
            client_sock.connect((ip, TRANSFER_PORT))
            
            # Send file info
            info = json.dumps({"filename": filename, "filesize": filesize})
            client_sock.sendall(info.encode('utf-8').ljust(1024))
            
            
            self.status_var.set(f"보내는 중: {filename}...")
            
            # Init progress bar
            self.root.after(0, lambda: self.progress.config(maximum=filesize, value=0))

            sent_size = 0
            start_time = time.time()
            with open(file_path, 'rb') as f:
                while not self.cancel_event.is_set():
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    client_sock.sendall(data)
                    sent_size += len(data)
                    
                    # Update progress and ETA
                    elapsed_time = time.time() - start_time
                    if elapsed_time > 0:
                        speed = sent_size / elapsed_time
                        remaining_bytes = filesize - sent_size
                        eta_seconds = remaining_bytes / speed if speed > 0 else 0
                        
                        self.root.after(0, lambda v=sent_size: self.progress.config(value=v))
                        
                        if sent_size % (BUFFER_SIZE * 10) == 0: # Update text less frequently
                            percentage = (sent_size / filesize) * 100
                            status_msg = f"보내는 중: {percentage:.1f}% (ETA: {int(eta_seconds)}초)"
                            self.root.after(0, lambda s=status_msg: self.status_var.set(s))

            if self.cancel_event.is_set():
                self.status_var.set("취소됨")
                self.log(f"전송 취소됨: {filename}")
                self.root.after(0, lambda: self.progress.config(value=0))
                return

            elapsed = time.time() - start_time
            self.status_var.set(f"완료: {filename} 전송됨")
            self.root.after(0, lambda: self.progress.config(value=0)) # Reset progress bar
            self.log(f"전송 완료: {filename} ({elapsed:.2f}초 걸림)")
            messagebox.showinfo("완료", f"{filename}을(를) 성공적으로 보냈습니다.")
            
            self.selected_file_path = ""
            self.file_label.config(text="선택된 파일 없음", fg="blue")
            self.send_btn.config(state=tk.DISABLED)
            
        except Exception as e:
            if not self.cancel_event.is_set():
                self.status_var.set(f"오류: {str(e)}")
                self.log(f"전송 실패: {str(e)}")
                self.root.after(0, lambda: self.progress.config(value=0))
                messagebox.showerror("오류", f"파일 전송 실패: {e}")
        finally:
            if self.transfer_socket:
                self.transfer_socket.close()
                self.transfer_socket = None
            self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))

    def receive_server(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(('0.0.0.0', TRANSFER_PORT))
        server_sock.listen(5)
        server_sock.settimeout(1.0)
        
        while not self.stop_threads.is_set():
            try:
                conn, addr = server_sock.accept()
                threading.Thread(target=self.handle_incoming_file, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue

    def handle_incoming_file(self, conn, addr):
        self.transfer_socket = conn
        try:
            self.log(f"연결 수신: {addr[0]}")
            info_data = conn.recv(1024).decode('utf-8').strip()
            info = json.loads(info_data)
            filename = info['filename']
            filesize = info['filesize']
            
            formatted_size = self.format_size(filesize)

            if messagebox.askyesno("파일 받기", f"{addr[0]}님으로부터 {filename} ({formatted_size})를 받으시겠습니까?"):

                base_name, extension = os.path.splitext(filename)
                save_path = os.path.join(RECEIVED_DIR, filename)
                
                counter = 1
                while os.path.exists(save_path):
                    save_path = os.path.join(RECEIVED_DIR, f"{base_name}_{counter}{extension}")
                    counter += 1

                self.status_var.set(f"받는 중: {filename}...")
                self.log(f"수신 시작: {filename} -> {save_path}")
                
                # Init progress bar
                self.root.after(0, lambda: self.progress.config(maximum=filesize, value=0))

                self.cancel_event.clear()
                self.root.after(0, lambda: self.cancel_btn.config(state=tk.NORMAL))

                received_size = 0
                start_time = time.time()
                with open(save_path, 'wb') as f:
                    while received_size < filesize and not self.cancel_event.is_set():
                        # Use a smaller timeout or non-blocking check if strictly needed,
                        # but closing socket usually interrupts recv immediately.
                        try:
                            data = conn.recv(min(BUFFER_SIZE, filesize - received_size))
                        except OSError: # Socket closed
                            break
                            
                        if not data:
                            break
                        f.write(data)
                        received_size += len(data)
                        
                        # Update progress and ETA
                        elapsed_time = time.time() - start_time
                        if elapsed_time > 0:
                            speed = received_size / elapsed_time
                            remaining_bytes = filesize - received_size
                            eta_seconds = remaining_bytes / speed if speed > 0 else 0
                            
                            self.root.after(0, lambda v=received_size: self.progress.config(value=v))
                            
                            if received_size % (BUFFER_SIZE * 10) == 0:
                                percentage = (received_size / filesize) * 100
                                status_msg = f"받는 중: {percentage:.1f}% (ETA: {int(eta_seconds)}초)"
                                self.root.after(0, lambda s=status_msg: self.status_var.set(s))

                if self.cancel_event.is_set():
                    self.log(f"수신 취소됨: {filename}")
                    self.status_var.set("취소됨")
                    self.root.after(0, lambda: self.progress.config(value=0))
                    # Optionally delete partial file
                    try:
                        os.remove(save_path)
                        self.log(f"부분 파일 삭제됨: {save_path}")
                    except:
                        pass
                    return

                self.status_var.set(f"완료: {filename} 받음")
                self.root.after(0, lambda: self.progress.config(value=0)) # Reset progress bar
                self.log(f"수신 완료: {save_path}")
                messagebox.showinfo("완료", f"{filename}을(를) '{RECEIVED_DIR}' 폴더에 받았습니다.")
            else:
                self.log(f"수신 거부됨: {filename}")
                self.status_var.set("거부됨")

        except Exception as e:
            if not self.cancel_event.is_set():
                self.status_var.set(f"수신 오류: {str(e)}")
                self.log(f"수신 실패: {str(e)}")
                self.root.after(0, lambda: self.progress.config(value=0))
        finally:
            if self.transfer_socket:
                self.transfer_socket.close()
                self.transfer_socket = None
            self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PFileTransferApp(root)
    root.mainloop()
