from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import sqlite3
import json  # Import the json module to serialize/deserialize dictionaries
import hashlib
import secrets

def hash_data(data):
    """
    Hashes the given data using SHA-256 and returns the hexadecimal hash value.
    The data must be in bytes (e.g., from secrets.token_bytes()).
    """
    # Create SHA-256 hash object
    hash_object = hashlib.sha256()
    
    # Update the hash object with the data (binary data)
    hash_object.update(data)
    
    # Return the hexadecimal digest of the hash
    return hash_object.hexdigest()

def setup_database():
    conn = sqlite3.connect("nodes.db")  # Create or connect to the database
    cursor = conn.cursor()
    # Create table to store node information
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            data TEXT
        )
    """)
    conn.commit()
    return conn

def update_node(conn, address, new_data):
    cursor = conn.cursor()
    # Serialize the dictionary to a JSON string
    serialized_data = json.dumps(new_data)
    
    # Update the node's data in the database
    cursor.execute("UPDATE nodes SET data = ? WHERE address = ?", (serialized_data, address))
    conn.commit()

def add_node(conn, address):
    cursor = conn.cursor()
    try:
        # Serialize the dictionary to a JSON string
        data = json.dumps({"hey": "ezaezaezae"})
        cursor.execute("INSERT INTO nodes (address, data) VALUES (?, ?)", (address, data))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Node already exists

# Fetch all nodes from the database
def get_all_nodes(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM nodes")
    return cursor.fetchall()

# HTTP Request Handler
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        conn = sqlite3.connect("nodes.db")
        nodes = get_all_nodes(conn)
        random_hashes = [hash_data(secrets.token_bytes(32)) for _ in range(100)]
        
        for node in nodes:
            address = node[1]
            new_data = {"hash": random_hashes.pop(0)}
            update_node(conn, address, new_data)
        
        nodes_html = "".join(f"<li>{node[1]}: {json.loads(node[2])}</li>" for node in nodes)

        response = f"""
        <html>
            <body>
                <h1>Server running on port {self.server.server_port}</h1>
                <h2>Registered Nodes:</h2>
                <ul>{nodes_html}</ul>
            </body>
        </html>
        """
        self.wfile.write(response.encode())
        conn.close()

def start_server(port):
    server_address = ("localhost", port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Server running on http://localhost:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    ports = []
    ports += [40000 + i for i in range(1, 47)]  # Generate ports from 40001 to 40046
    ip = "127.0.0.1"
    
    # Setup the database and insert nodes
    conn = setup_database()
    for port in ports:
        address = f"{ip}:{port}"
        add_node(conn, address)
    conn.close()  # Close initial connection after adding nodes

    # Start servers on all the ports
    threads = []
    for port in ports:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nShutting down servers.")
