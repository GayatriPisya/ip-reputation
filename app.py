from flask import Flask, render_template, request
import requests

ABUSEIPDB_KEY = "5a73927f75be965b1168f3390c7f9a6c0d36e52f37d3594e4c9328edc106bd526b61f93c618a6afe"
OTX_KEY = "6123dad1431816337d18ae34aca8ea8538de1571d464599beec821dd5200ed87"

app = Flask(__name__)

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    data = response.json().get("data", {})
    return {
        "IP": ip,
        "Abuse Score": data.get("abuseConfidenceScore", "N/A"),
        "Country": data.get("countryCode", "N/A"),
        "Usage Type": data.get("usageType", "N/A")
    }

def check_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    pulses = [pulse["name"] for pulse in data.get("pulse_info", {}).get("pulses", [])]
    return {
        "Malicious Pulses": len(pulses),
        "Pulse Names": ", ".join(pulses[:3]) or "None"
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip = request.form.get("ip")
        abuse_result = check_abuseipdb(ip)
        otx_result = check_otx(ip)
        return render_template("result.html", ip=ip, abuse=abuse_result, otx=otx_result)
    return render_template("index.html")

if __name__ != "__main__":
    application = app
