from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)

def rdu(value):
    return str(value).replace('__', '')

@app.route('/QRGenerator', methods=['GET', 'POST'])
def QRGenerator():
    if request.method == 'GET':
        services = 'Test service'
        return render_template('QRGenerator.html', services=services)

    elif request.method == 'POST':
        qr_link = rdu(request.args.get('qr_link'))
        print(qr_link, "\n")
        HTML = f"{{% extends 'temporary_invoice.html' %}}{{% block parameter1 %}}"
        HTML += '{}'.format(qr_link)
        HTML += '{% endblock %}'
        print(HTML)
        rendered_template = render_template_string(HTML)

        return rendered_template
    else:
        'Method Not Allowed', 405

if __name__ == '__main__':
    app.run(debug=True)