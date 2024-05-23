from flask import Flask, request, render_template_string

app = Flask(__name__)

def rdu(value):
    return str(value).replace('__', '')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        qr_link = rdu(request.form['qr_link'])
        HTML = '{}'.format(qr_link)
        rendered_template = render_template_string(HTML)
        return rendered_template
    else:
        'Method Not Allowed', 405


1
if __name__ == '__main__':
    app.run(debug=True)