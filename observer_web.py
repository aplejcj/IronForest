from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from datetime import datetime
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_for_ironforest'
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/log', methods=['POST'])
def receive_log():
    try:
        data = request.get_json()
        if not data or 'log_msg' not in data:
            return jsonify({"status": "error", "message": "Invalid data format"}), 400

        log_msg = data.get('log_msg')
        
        log_entry = {
            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "message": log_msg
        }
        
        socketio.emit('new_log', log_entry)
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print("--- IronForest Web Dashboard ---")
    print("Access it at: http://127.0.0.1:10000")
    print("Waiting for node connections...")
    socketio.run(app, host='0.0.0.0', port=10000)