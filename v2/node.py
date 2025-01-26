import sqlite3
import requests
import json

# Connect to the SQLite database
CONN = sqlite3.connect("nodes.db")

def update_node(conn, address, new_data):
    cursor = conn.cursor()
    # Serialize the dictionary to a JSON string
    serialized_data = json.dumps(new_data)
    
    # Update the node's data in the database
    cursor.execute("UPDATE nodes SET data = ? WHERE address = ?", (serialized_data, address))
    conn.commit()


def get_all_nodes():
    cursor = CONN.cursor()
    cursor.execute("SELECT * FROM nodes")
    return cursor.fetchall()

# Fetch all nodes from the database
nodes = get_all_nodes()
print("Checking nodes...")

# Loop through each node and check its status
for num, adrr, status in nodes:
    try:
        # Send a GET request to the node address (which includes IP and port)
        resp = requests.get(f"http://{adrr}")
        
        # If the response status code is 200, the node is up
        if resp.status_code == 200:
            print(f"Node {num} ({adrr}) is up")
            update_node(CONN, adrr, {"status": "up"})
    except requests.exceptions.RequestException as e:
        # Handle any exceptions (network issues, etc.)
        print(f"Node {num} ({adrr}) is down. Error: {e}")

# Close the database connection
CONN.close()
