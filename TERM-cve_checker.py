"""
Author: Adrien RICQUE
Version: 1.0
Creation Date: 23/07/2024

What's for?: Check if the site opencve has declared critical cve on particular techno
"""

import os
from datetime import date
#from pyfiglet import Figlet

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

import requests
import json
import base64

import re
from bs4 import BeautifulSoup

# def banner():
#     """Banner creator"""
#     custom_fig = Figlet(font='graffiti')
#     print(custom_fig.renderText('CVE Checker'))

def menu():
    """Menu to select your need"""
    #banner()
    print("""
    Welcome to the CVE checker!
    1) Google Chrome
    2) Jira
    3) Eset Antivirus
    4) Generate a detail report on a particular CVE
    """)
    choice = input("So? What do you want to do? ")
    match choice:
        case '1':
            check_google_chrome_cve()
        case '2':
            check_jira_cve()
        case '3':
            check_eset_cve()
        case '4':
            generate_detail_cve_report()
        case _:
            print("Invalid choice. Please try again.")
            menu()

def check_google_chrome_cve():
    """Check the critical CVE for Google Chrome"""
    url = 'https://www.opencve.io/cve?tag=&cvss=critical&search=google+chrome'
    cve_id = extract_cve_id(url)
    cvss = extract_cvss_v3_scores(url)
    update_date = extract_update_dates(url)
    technology = "google-chrome"

    number = len(cve_id)
    if number < 1:
        print("There is no Critical CVE...")
        return

    # Ask the user if they want to generate the report
    generate_report = input("Do you want to generate the report? (o/n) ")
    if generate_report.lower() != 'o':
        print("The report hasn't been generated!")
        return

    # Create a filename for the output file
    actual_date = date.today().strftime("%Y_%m_%d")
    report_name = f"Report-{actual_date}-{technology}.txt"
    print(report_name)

    # Verify if the report exists to adapt the writable mode
    write_mode = is_report_exist(report_name)

    # Open the file in write mode
    with open(report_name, write_mode) as f:
        # Write the header line
        f.write('Index | Id | CVSS v3 Score | Update Date\n')

        # Write the results to the file
        for i in range(number):
            num_cve = str(i + 1)  # Use i + 1 to start the index at 1
            result = f'{num_cve} | {cve_id[i]} | {cvss[i]} | {update_date[i]}'
            f.write(result + '\n')

    # Display a message to confirm that the file has been written
    print(f'All results have been written in {report_name}')


def check_jira_cve():
    """Check the critical CVE for Jira"""
    url = 'https://www.opencve.io/cve?tag=&cvss=critical&search=jira'
    cve_id = extract_cve_id(url)
    cvss = extract_cvss_v3_scores(url)
    update_date = extract_update_dates(url)
    technology = "jira"

    number = len(cve_id)
    if number < 1:
        print("There is no Critical CVE...")
        return

    # Ask the user if they want to generate the report
    generate_report = input("Do you want to generate the report? (o/n) ")
    if generate_report.lower() != 'o':
        print("The report hasn't been generated!")
        return

    # Create a filename for the output file
    actual_date = date.today().strftime("%Y_%m_%d")
    report_name = f"Report-{actual_date}-{technology}.txt"
    print(report_name)

    # Verify if the report exists to adapt the writable mode
    write_mode = is_report_exist(report_name)

    # Open the file in write mode
    with open(report_name, write_mode) as f:
        # Write the header line
        f.write('Index | Id | CVSS v3 Score | Update Date\n')

        # Write the results to the file
        for i in range(number):
            num_cve = str(i + 1)  # Use i + 1 to start the index at 1
            result = f'{num_cve} | {cve_id[i]} | {cvss[i]} | {update_date[i]}'
            f.write(result + '\n')

    # Display a message to confirm that the file has been written
    print(f'All results have been written in {report_name}')


def check_eset_cve():
    """Check the critical CVE for Eset Antivirus"""
    url = 'https://www.opencve.io/cve?tag=&cvss=critical&search=eset+antivirus'
    cve_id = extract_cve_id(url)
    cvss = extract_cvss_v3_scores(url)
    update_date = extract_update_dates(url)
    technology = "eset-antivirus"

    number = len(cve_id)
    if number < 1:
        print("There is no Critical CVE...")
        return

    # Ask the user if they want to generate the report
    generate_report = input("Do you want to generate the report? (o/n) ")
    if generate_report.lower() != 'o':
        print("The report hasn't been generated!")
        return

    # Create a filename for the output file
    actual_date = date.today().strftime("%Y_%m_%d")
    report_name = f"Report-{actual_date}-{technology}.txt"
    print(report_name)

    # Verify if the report exists to adapt the writable mode
    write_mode = is_report_exist(report_name)

    # Open the file in write mode
    with open(report_name, write_mode) as f:
        # Write the header line
        f.write('Index | Id | CVSS v3 Score | Update Date\n')

        # Write the results to the file
        for i in range(number):
            num_cve = str(i + 1)  # Use i + 1 to start the index at 1
            result = f'{num_cve} | {cve_id[i]} | {cvss[i]} | {update_date[i]}'
            f.write(result + '\n')

    # Display a message to confirm that the file has been written
    print(f'All results have been written in {report_name}')


def is_report_exist(report):
    try:
        result = os.path.exists(report)
        print(result)
        if result:
            write_mode = 'a'
        else:
            write_mode = 'x'
        return write_mode
    except OSError as errors:
        print(errors)


def generate_detail_cve_report():
    cve = input('Choose a CVE: ')
    report_detail = f"{cve}_details-report.pdf"
    print(report_detail)
    data = get_information(cve)
    generate_pdf_report(data, report_detail)
    print("Everything looks good!")


def generate_pdf_report(data, output_filename):
    # Create a PDF document
    doc = SimpleDocTemplate(output_filename, pagesize=letter)
    story = []

    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    normal_style = styles['Normal']

    # Add the title
    story.append(Paragraph("CVE Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    # Add the CVE details
    story.append(Paragraph(f"<b>ID:</b> {data['id']}", normal_style))
    story.append(Paragraph(f"<b>Summary:</b> {data['summary']}", normal_style))
    story.append(Paragraph(f"<b>Created At:</b> {data['created_at']}", normal_style))
    story.append(Paragraph(f"<b>Updated At:</b> {data['updated_at']}", normal_style))
    story.append(Paragraph(f"<b>CVSS v3:</b> {data['cvss']['v3']}", normal_style))

    # Add the CVSS metrics details
    if data['raw_nvd_data']['metrics']['cvssMetricV31']:
        cvss_metric = data['raw_nvd_data']['metrics']['cvssMetricV31'][0]['cvssData']
        story.append(Paragraph(f"<b>Base Score:</b> {cvss_metric['baseScore']}", normal_style))
        story.append(Paragraph(f"<b>Base Severity:</b> {cvss_metric['baseSeverity']}", normal_style))
        story.append(Paragraph(f"<b>Vector String:</b> {cvss_metric['vectorString']}", normal_style))

    # Add the references
    story.append(Paragraph("<b>References:</b>", normal_style))
    for reference in data['raw_nvd_data']['references']:
        story.append(Paragraph(f"<a href='{reference['url']}'>{reference['url']}</a>", normal_style))

    # Add the descriptions
    story.append(Paragraph("<b>Descriptions:</b>", normal_style))
    for description in data['raw_nvd_data']['descriptions']:
        story.append(Paragraph(f"<b>{description['lang']}:</b> {description['value']}", normal_style))

    # Build the PDF document
    doc.build(story)

def get_information(cve_id):
    url = f"https://www.opencve.io/api/cve/{cve_id}"
    payload = {}
    encoded_credentials = login_opencve()
    headers = {
        'Authorization': f'Basic {encoded_credentials}',
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    print(response.text)
    data = response.json()
    save_in_json(data)
    return data

def save_in_json(data):
    with open('cve_details.json', 'w') as f:
        json.dump(data, f, indent=4)

def login_opencve():
    username = input('Email: ')
    password = input('Password: ')
    # Encode the login and password
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return encoded_credentials

def extract_cve_id(url):
    # CVE regular expression
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    try:
        # Query the website and return the HTML
        page = requests.get(url)
        page.raise_for_status()

        # Search for CVE references using RegEx
        cves = re.findall(cve_pattern, page.text)

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


if __name__ == "__main__":
    menu()
