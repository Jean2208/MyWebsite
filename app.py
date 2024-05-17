from flask import Flask, render_template, request, make_response, abort, send_file
from itsdangerous import URLSafeSerializer
import os
import random

app = Flask(__name__, template_folder=".")


# Set a bytes object to the secret key attribute of the app instance
app.secret_key = b'PcBE2u6tBomJmDMwUbRzO18I07A'
# Serialize the data with a secret key
serializer = URLSafeSerializer(app.secret_key)

# Print the serialized user cookie
serialized_value = serializer.dumps("user")
print("Serialized User Cookie:", serialized_value)

# Print the serialized admin cookie
serialized_value = serializer.dumps("admin")
print("Serialized Admin Cookie:", serialized_value)



@app.route('/')
def index():
    # Get the Remote_Addr header from the request
    client_ip = request.remote_addr
    # Check if the request comes from localhost, if it's grant them admin cookie.
    # Otherwise give them user cookie.
    is_admin = True if client_ip in ['127.0.0.1', '::1'] else False
    token = "admin" if is_admin else "user"
    # Serialize "admin" or "user" with the secret key.
    serialized_value = serializer.dumps(token)

    # Make the reponse and assign a value to the 'is_admin' cookie.
    response = make_response(render_template('index.html', is_admin=token))
    response.set_cookie('is_admin', serialized_value, httponly=False)

    return response

@app.route('/dashboard', methods=['GET', 'POST'])
def admin():
    if serializer.loads(request.cookies.get('is_admin')) == "user":
        return abort(401)

    script_output = ""

    if request.method == 'POST':
        date = request.form.get('date')
        if date:
            script_output = os.popen(f'bash report.sh {date}').read()

    return render_template('dashboard.html', script_output=script_output)

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        message = request.form.get('message')
        if ("<" in message and ">" in message) or ("{{" in message and "}}" in message):
            request_info = {
                "Method": request.method,
                "URL": request.url,
                "Headers": format_request_info(dict(request.headers)),
            }

            formatted_request_info = format_request_info(request_info)
            html = render_template('hackattempt.html', request_info=formatted_request_info)

            filename = f'{random.randint(1, 99999999999999999999999)}.html'
            with open(os.path.join(hacking_reports_dir, filename), 'w', encoding='utf-8') as html_file:
                html_file.write(html)

            return html

    return render_template('support.html')

@app.route('/hacking_reports/<int:report_number>')
def hacking_reports(report_number):
    report_file = os.path.join(hacking_reports_dir, f'{report_number}.html')

    if os.path.exists(report_file):
        return send_file(report_file)
    else:
        return "Report not found", 404

def format_request_info(info):
    formatted_info = ''
    for key, value in info.items():
        formatted_info += f"<strong>{key}:</strong> {value}<br>"
    return formatted_info

def format_form_data(form_data):
    formatted_data = {}
    for key, value in form_data.items():
        formatted_data[key] = value
    return formatted_data

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)