from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}

app._static_folder = os.path.abspath("/opt/app/static/")

def rdu(value):
    return str(value).replace('__', '')

def sanitize(input):
                sanitized_output = re.sub(r'[^a-zA-Z0-9@. ]', '', input)
                return sanitized_output

app.jinja_env.undefined = StrictUndefined
app.jinja_env.filters['remove_double_underscore'] = rdu

valid_invoice_ids = []

def add_valid_invoice_id(invoice_id):
    valid_invoice_ids.append(invoice_id)

def get_allowed_invoice_ids():
    return valid_invoice_ids

def validate_invoice_id(provided_id):
    allowed_invoice_ids = get_allowed_invoice_ids()  
    return provided_id in allowed_invoice_ids

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/quote')
def quote():
    return render_template('quote.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/choose')
def choose():
    return render_template('choose.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/EditServices', methods=['GET', 'POST'])
def editservices():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        if request.method == 'GET':
            with pymysql.connect(**db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT service_name FROM services')
                    services = [row[0] for row in cursor.fetchall()]
            return render_template('EditServices.html', services=services)
        elif request.method == 'POST':
            selected_service = request.form['selected_service']
            return redirect(url_for('edit_service_details', service=selected_service))
        else:
            return make_response('Invalid request format.', 400)
    else:
        return redirect(url_for('index'))

@app.route('/EditServiceDetails/<service>', methods=['GET', 'POST'])
def edit_service_details(service):
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        if request.method == 'GET':
            with pymysql.connect(**db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT * FROM services WHERE service_name = %s', (service,))
                    result = cursor.fetchone()
            return render_template('EditServiceDetails.html', service=result)
        elif request.method == 'POST':
            description = request.form['description']
            with pymysql.connect(**db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute('UPDATE services SET service_description = %s WHERE service_name = %s', (description, service))
                    conn.commit()
            return redirect(url_for('editservices'))
        else:
            return make_response('Invalid request format.', 400)
    else:
        return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        return render_template('dashboard.html')
    else:
        return redirect(url_for('index'))

@app.route('/sendMessage', methods=['POST'])
def quote_requests():
    
    conn = pymysql.connect(**db_config)

    cursor = conn.cursor()
    checkboxes = request.form.getlist('service')
    email = request.form.get('email')

    checkboxes_str = ', '.join(checkboxes)

    query = "INSERT INTO quote_requests (checkboxes, email) VALUES (%s, %s)"
    cursor.execute(query, (checkboxes_str, email))
    conn.commit()
 
    cursor.close()
    conn.close()

    return render_template('quote_requests_thankyou.html')

@app.route('/QuoteRequests', methods=['GET'])
def get_quote_requests():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        query = "SELECT * FROM quote_requests"
        cursor.execute(query)
        data = cursor.fetchall()

        cursor.close()
        conn.close()

        ids = []

        for row in data:
            ids.append(row[0])

        return render_template('QuoteRequests.html', ids=ids)


@app.route('/QuoteRequests/<int:quote_id>', methods=['GET'])
def get_single_quote_request(quote_id):
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        query = "SELECT * FROM quote_requests WHERE quote_id = %s"
        cursor.execute(query, (quote_id,))
        data = cursor.fetchall()

        cursor.close()
        conn.close()

        for row in data:
            checkboxes = row[1]
            email = row[2]

        return render_template('QuoteRequestDetail.html', email=email, services=checkboxes)

@app.route('/QuoteRequests/delete/<int:quote_id>', methods=['GET'])
def delete_single_quote_request(quote_id):
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        query = "DELETE FROM quote_requests WHERE quote_id = %s"
        cursor.execute(query, (quote_id,))
        data = cursor.fetchall()

        conn.commit()

        cursor.close()
        conn.close()

        return redirect(url_for('get_quote_requests'))

@app.route('/QRInvoice/<filename>')
def QRInvoice(filename):
    return render_template(filename)

@app.route('/Invoice/<filename>')
def Invoice(filename):
    return render_template(filename)

random_number = None

@app.route('/InvoiceGenerator', methods=['GET', 'POST'])
def InvoiceGenerator():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        if request.method == 'GET':
            with pymysql.connect(**db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT service_name FROM services')
                    services = [row[0] for row in cursor.fetchall()]
            return render_template('InvoiceGenerator.html', services=services)
        if request.method == 'POST':
            random_number = ''.join(random.choices(string.digits, k=10))
            add_valid_invoice_id(random_number)
            
            quantity_chosen = sanitize(request.form['qty'])
            client_email = sanitize(request.form['email-address'])
            client_address = sanitize(request.form['address'])
            project_name = sanitize(request.form['project'])
            client_name = sanitize(request.form['client'])
            service_chosen = sanitize(request.form['selected_service'])
            
            rendered_template = render_template('template_invoice.html', service_chosen=service_chosen, project_name=project_name, client_name=client_name, client_address=client_address, client_email=client_email, quantity_chosen=quantity_chosen)                     
            
            with open(os.path.join('/opt/app/templates/', 'temporary_invoice.html'), 'w') as html_file:
                html_file.write(rendered_template)
            
            with open(os.path.join('/opt/app/templates/', 'temporary_invoice.html'), 'r') as html_file:
                modified_content = html_file.read()

            qr_code_img_tag = '''<div class="qr-code-container"><div class="qr-code"><img src="data:image/png;base64,{% block parameter1 %}{% endblock %}" alt="QR Code"></div>'''
            modified_content = modified_content.replace('</body>', f'{qr_code_img_tag}\n</body>')

            with open(os.path.join('/opt/app/templates/', 'temporary_invoice.html'), 'w') as html_file:
                html_file.write(modified_content)

            return render_template('Invoice.html', invoice_id=random_number)
        
        return render_template('InvoiceGenerator.html')
    else:
        return redirect(url_for('index'))

@app.route('/QRGenerator', methods=['GET', 'POST'])
def QRGenerator():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        if request.method == 'GET':
            with pymysql.connect(**db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT service_name FROM services')
                    services = [row[0] for row in cursor.fetchall()]
            return render_template('QRGenerator.html', services=services)

        if request.method == 'POST':
            form_type = request.form['form_type']
            if form_type == 'invoice_id':
                invoice_id = request.form['invoice_id']
                if validate_invoice_id(invoice_id):
                    filename = f'invoice_{invoice_id}.html'
                    with open(os.path.join('/opt/app/templates/', 'temporary_invoice.html'), 'r') as html_file:
                        temp_invoice = html_file.read()
                    with open(os.path.join('/opt/app/templates/', filename), 'w') as html_file:
                        html_file.write(temp_invoice)

                    invoice_url = url_for('QRInvoice', filename=filename, _external=True)
                    qr_image = pyqrcode.create(invoice_url)
                    qr_image.png(os.path.join('/opt/app/static/qr_code', f'qr_code_{invoice_id}.png'), scale=2, module_color=[0, 0, 0, 128], background=[0xff, 0xff, 0xff])
                    png_link = url_for('static', filename=f'qr_code/qr_code_{invoice_id}.png', _external=True)
                    
                    return render_template('QRGenerator2.html', png_link=png_link)
            elif form_type == 'scannable_invoice':
                qr_link = rdu(request.form['qr_link'])
                if 'http://capiclean.htb' in qr_link:
                    qr = requests.get(qr_link)
                    image_content = qr.content
                    qr_url = base64.b64encode(image_content).decode('utf-8')
                
                    HTML = f"{{% extends 'temporary_invoice.html' %}}{{% block parameter1 %}}"
                    HTML += '{}'.format(qr_url)
                    HTML += '{% endblock %}'
                    rendered_template = render_template_string(HTML)
                    
                    return rendered_template
                else:
                    HTML = f"{{% extends 'temporary_invoice.html' %}}{{% block parameter1 %}}"
                    HTML += '{}'.format(qr_link)
                    HTML += '{% endblock %}'
                    rendered_template = render_template_string(HTML)
                    
                    return rendered_template

            else:
                return redirect(url_for('QRGenerator'))
        return render_template('QRGenerator.html')
    else:
        return redirect(url_for('index'))



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', error=False)
    elif request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT role_id FROM users WHERE username=%s AND password=%s', (username, password))
                result = cursor.fetchone()

                if result is None:
                    return render_template('login.html',error='Invalid username or password')
                else:
                    session['role'] = result[0]
                    if session['role'] == hashlib.md5(b'admin').hexdigest():
                        return redirect(url_for('dashboard'))
                    else:
                        return redirect(url_for('/'))
    else:
        return make_response('Invalid request format.', 400)


if __name__ == '__main__':
    app.run(port=3000)
