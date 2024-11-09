import os
import requests
from flask import Flask, request, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for flash messages

# Define upload folder path
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Expanded allowed file extensions
ALLOWED_EXTENSIONS = {
    'exe', 'bat', 'doc', 'docx', 'pdf', 'zip', 'txt', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'jpeg', 'png', 'gif', 'rar', '7z', 'tar', 'gz', 'html', 'js', 'css', 'php'
}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Replace with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = '50fadbf5f887eddae4f519f8def155efc1f0c98d252051c4d42c3b2124d61a32'

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            flash('File successfully uploaded')

            # Process file using VirusTotal
            analysis_result = process_file(file_path)
            
            # Display the analysis result in a flash message
            flash(f'Malware Analysis Result: {analysis_result}')

            # Delete the file after processing
            os.remove(file_path)
            flash('File processed and deleted')

            return redirect(url_for('index'))
        else:
            flash('Invalid file type')
            return redirect(request.url)

    return render_template('index.html')

# Upload the file to VirusTotal and get an analysis report
def process_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post(url, headers=headers, files=files)

    # Print the response for debugging purposes
    print("VirusTotal Response Status Code:", response.status_code)
    print("Response Body:", response.text)

    if response.status_code == 200:
        file_id = response.json()["data"]["id"]
        return get_analysis(file_id)
    else:
        return f"File analysis failed: {response.text}"

# Retrieve the analysis result using the file ID
def get_analysis(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data["data"]["attributes"]["stats"]["malicious"]

        if malicious_count > 0:
            return f"Malicious file detected! (Malicious count: {malicious_count})"
        else:
            return "File is clean"
    else:
        return "Error retrieving analysis"

if __name__ == '__main__':
    app.run(debug=True)


