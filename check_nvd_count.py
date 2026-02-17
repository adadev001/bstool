import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "resultsPerPage": 1
}

response = requests.get(url, params=params)
response.raise_for_status()
data = response.json()

print("totalResults =", data["totalResults"])
