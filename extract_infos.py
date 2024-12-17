"""
Author: Adrien RICQUE
Version: 1.3
Creation Date: 23/07/2024

Update Date: 29/07/2024
Actor: Adrien RICQUE

"""

from re import findall
import requests
from bs4 import BeautifulSoup
284
def extract_cve_id(url):
    # CVE regular expression
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    try:
        # Query the website and return the HTML
        page = requests.get(url)
        page.raise_for_status()

        # Search for CVE references using RegEx
        cves = findall(cve_pattern, page.text)

        # I found order to be important sometimes, as the most severely rated CVEs are often listed first on the page
        cves = list(dict.fromkeys(cves))
        return cves
    except requests.exceptions.HTTPError as errhttp:
        print("HTTP Error")
        print(errhttp.args[0])

def extract_cvss_v3_scores(url):
    try:
        # Fetch the webpage content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all the span elements with class 'label label-warning', 'label label-danger', or 'label label-critical'
        score_elements = soup.find_all('span', class_=['label label-danger', 'label label-critical'])

        # Extract the scores from the elements
        scores = [element.text for element in score_elements]
        return scores
    except requests.exceptions.HTTPError as errhttp:
        print("HTTP Error")
        print(errhttp.args[0])


def extract_update_dates(url):
    try:
        # Fetch the webpage content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all the span elements with class 'label label-warning', 'label label-danger', or 'label label-critical'
        dates = soup.find_all('td', class_='col-md-2 text-center')

        # Extract the scores from the elements
        update_dates = [element.text for element in dates]
        return update_dates
    except requests.exceptions.HTTPError as errhttp:
        print("HTTP Error")
        print(errhttp.args[0])