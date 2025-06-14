from flask import Flask, request, render_template
import numpy as np
import pandas as pd
import pickle
import requests
import socket
import tldextract
from datetime import datetime
import whois
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
import time
import os

from feature import FeatureExtraction  # Import the feature extraction class

# =========================
# Load the trained model
# =========================
MODEL_PATH = "pickle/model.pkl"
with open(MODEL_PATH, "rb") as file:
    gbc = pickle.load(file)

# =========================
# Initialize Flask app
# =========================
app = Flask(__name__)

# =========================
# Validate URL and add scheme if needed
# =========================
def validate_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = f"http://{url}"
    return url

# =========================
# Function to fetch URL details
# =========================
def fetch_url_details(url):
    try:
        # Extract domain information
        domain_info = tldextract.extract(url)
        full_domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Get IP address - this will fail if the domain is offline
        try:
            ip_address = socket.gethostbyname(full_domain)
        except socket.gaierror:
            # Domain couldn't be resolved - it's offline
            return {
                "status": "offline",
                "source_url": url,
                "ip_address": "Unavailable",
                "detection_date": datetime.now().strftime("%B %d, %Y, %I:%M:%S %p"),
                "certificate_details": "Unavailable",
                "location": "Unavailable",
                "hosting_provider": "Unavailable",
                "asn": "Unavailable"
            }
        
        # Fetch geolocation and hosting provider data
        ip_api_url = f"http://ip-api.com/json/{ip_address}"
        geo_data = requests.get(ip_api_url).json()
        location = geo_data.get("country", "Unknown") + ", " + geo_data.get("city", "Unknown")
        hosting_provider = geo_data.get("isp", "Unknown")
        
        # Fetch WHOIS information
        try:
            whois_info = whois.whois(full_domain)
        except Exception:
            whois_info = {"asn": "N/A"}
        
        # For demonstration purposes, we mock SSL certificate details.
        certificate_details = f"Let's Encrypt: {full_domain}"
        
        return {
            "status": "online",
            "source_url": url,
            "redirected_url": url,
            "ip_address": ip_address,
            "detection_date": datetime.now().strftime("%B %d, %Y, %I:%M:%S %p"),
            "certificate_details": certificate_details,
            "location": location,
            "hosting_provider": hosting_provider,
            "asn": whois_info.get("asn", "N/A")
        }
    except Exception as e:
        return {
            "status": "error",
            "error": f"An error occurred while fetching details: {str(e)}",
            "source_url": url,
            "ip_address": "Unavailable",
            "detection_date": datetime.now().strftime("%B %d, %Y, %I:%M:%S %p"),
            "certificate_details": "Unavailable",
            "location": "Unavailable",
            "hosting_provider": "Unavailable",
            "asn": "Unavailable"
        }

# =========================
# Route for the index page
# =========================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "")
        url = validate_url(url)
        
        # Fetch website details first to check if it's online
        website_info = fetch_url_details(url)
        
        # Always analyze the URL regardless of whether it's online or offline
        try:
            # Extract features from the URL
            extractor = FeatureExtraction(url)
            features_list = extractor.getFeaturesList()  # Should return a list of 30 features
            features = np.array(features_list).reshape(1, 30)
            
            # Create a dummy feature (for example, "Index") to match the 31 columns used during training
            dummy_feature = np.zeros((1, 1))
            features_with_dummy = np.hstack((dummy_feature, features))
            
            # Define the column names exactly as used during model training
            column_names = ['Index', 'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
                            'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
                            'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
                            'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
                            'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
                            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
                            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
                            'StatsReport']
            
            features_df = pd.DataFrame(features_with_dummy, columns=column_names)
            
            # Get prediction and probabilities from the model
            prediction = gbc.predict(features_df)[0]
            proba = gbc.predict_proba(features_df)[0]
            pro_non_phishing = proba[1]  # Adjust according to your training
            
            result_text = "It is {0:.2f}% safe to go".format(pro_non_phishing * 100)
            
            # If the website is offline, return with offline status but include safety analysis
            if website_info.get("status") == "offline":
                return render_template("index.html", 
                                      url=url,
                                      website_info=website_info,
                                      is_offline=True,
                                      xx=round(pro_non_phishing, 2),
                                      prediction=prediction,
                                      result_text=result_text)
            
            # If online, capture screenshot and continue as normal
            try:
                capture_screenshot(url)
            except Exception as e:
                print(f"Screenshot error: {e}")
                # Continue even if screenshot fails
            
            return render_template("index.html",
                                   xx=round(pro_non_phishing, 2),
                                   url=url,
                                   prediction=prediction,
                                   result_text=result_text,
                                   website_info=website_info)
        except Exception as e:
            error_msg = f"Error occurred: {e}"
            return render_template("index.html", xx=-1, error=error_msg, url=url, website_info=website_info)
    
    return render_template("index.html", xx=-1)

# =========================
# Function to capture a screenshot using Selenium
# =========================
def capture_screenshot(url):
    url = validate_url(url)
    screenshot_dir = os.path.join("static", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1280,1024")
    
    # Adjust the path to your ChromeDriver if necessary.
    service = ChromeService()  # Looks in PATH by default
    driver = webdriver.Chrome(service=service, options=chrome_options)
    try:
        driver.get(url)
        time.sleep(3)  # Wait for the page to load
        parsed = urlparse(url)
        screenshot_path = os.path.join(screenshot_dir, f"{parsed.netloc}.png")
        driver.save_screenshot(screenshot_path)
    finally:
        driver.quit()

# =========================
# Run the Flask application
# =========================
if __name__ == "__main__":
    app.run(debug=True)
