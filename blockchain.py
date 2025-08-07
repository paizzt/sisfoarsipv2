import hashlib
import json
from time import time
from uuid import uuid4
import os

class Blockchain:
    def __init__(self, chain_file='blockchain_data.json'):
        self.chain_file = chain_file
        self.chain = []
        self.current_transactions = []
        
        # Coba muat chain dari file saat inisialisasi
        self.load_chain_from_file()

        # Jika chain kosong setelah loading (file tidak ada/kosong), buat genesis block
        if not self.chain:
            self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'data': {}
        }
        self.current_transactions = []
        self.chain.append(block)
        
        # Simpan perubahan ke file setiap kali blok baru dibuat
        self.save_chain_to_file()
        
        return block

    def add_user_data_to_block(self, block, user_data):
        if 'data' not in block:
            block['data'] = {}
        data_id = str(uuid4()).replace('-', '')
        block['data'][data_id] = user_data
        # Simpan perubahan ke file setelah data ditambahkan ke blok
        self.save_chain_to_file()

    # --- FUNGSI BARU UNTUK PERSISTENSI DATA ---
    def save_chain_to_file(self):
        """Menyimpan seluruh chain ke dalam sebuah file JSON."""
        try:
            with open(self.chain_file, 'w') as f:
                json.dump(self.chain, f, indent=4)
        except Exception as e:
            print(f"Gagal menyimpan chain ke file: {e}")

    def load_chain_from_file(self):
        """Memuat chain dari file JSON jika ada."""
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, 'r') as f:
                    self.chain = json.load(f)
            except json.JSONDecodeError:
                print("Peringatan: File chain ditemukan tapi kosong atau rusak. Memulai dengan chain baru.")
                self.chain = []
            except Exception as e:
                print(f"Gagal memuat chain dari file: {e}")
                self.chain = []

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def find_user_by_email(self, email):
        # Cari dari blok terbaru untuk mendapatkan data terupdate (misal: password baru)
        for block in reversed(self.chain):
            if 'data' in block and block['data']:
                for data_entry in block['data'].values():
                    if isinstance(data_entry, dict) and data_entry.get('email') == email:
                        # Kita hanya butuh data terakhir yang cocok
                        return data_entry
        return None