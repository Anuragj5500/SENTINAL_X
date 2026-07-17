import requests

WEBHOOK_URL = "YOUR_SLACK_WEBHOOK_URL_HERE"

payload = {
    "text": "🚨 SentinelX Test Alert!\nSlack integration is working successfully."
}

response = requests.post(WEBHOOK_URL, json=payload)

print("Status Code:", response.status_code)
print("Response:", response.text)