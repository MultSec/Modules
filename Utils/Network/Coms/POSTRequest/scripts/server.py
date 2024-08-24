from flask import Flask, request

app = Flask(__name__)

@app.route('/test', methods=['POST'])
def test_endpoint():
    print(f'Received: {request.data.decode("utf-8")}')  # Assuming UTF-8 encoding
    return "Request received successfully!"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)