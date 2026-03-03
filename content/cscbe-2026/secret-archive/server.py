from Crypto.Cipher import AES
import secrets
from gzip import compress
import logging
import socketserver
HOST, PORT = "0.0.0.0", 1339

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

with open("file.gif", 'rb') as fin:
    IMAGE = fin.read()

class ChallengeHandler(socketserver.StreamRequestHandler):
    def handle(self):
        key = secrets.token_bytes(32)
        cipher = AES.new(key, AES.MODE_CTR)
        while True:
            try:
                archives = []
                
                self.request.sendall(b"Send me your files in hex format:\n> ")
                for _ in range(1000):
                    user_input = self.rfile.readline(5000).rstrip().decode()
                    if user_input == "":
                        break
                    input_file = bytes.fromhex(user_input)
                    archives.append(cipher.encrypt(compress(IMAGE + input_file)).hex().encode())
                    
                response = b"\n".join(archives)
                self.request.sendall(b"Here are your secret archives:\n")
                self.request.sendall(response+b"\n")
                
            except Exception as e:
                logging.error(f"Error: {e}")
                self.request.sendall(b"\nInvalid Input.\n")
                
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with ThreadedTCPServer((HOST, PORT), ChallengeHandler) as server:
        logging.info(f"Challenge running on {HOST}:{PORT}")
        server.serve_forever()