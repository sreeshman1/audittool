from flask import request,render_template, flash, redirect, url_for, request
from app import app
from app.trace import trace_request

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"
@app.route('/trace', methods=['GET','POST'])
def trace():
    response = None
    link = None
    jaeger = None
    if request.method == 'POST':
        response, jaeger = trace_request(request.form['request'],"moment/save")
    return render_template('trace.html',response=response,jaeger=jaeger)
