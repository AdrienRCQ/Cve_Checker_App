"""
Author: Adrien RICQUE
Version: 1.3
Creation Date: 23/07/2024

Update Date: 29/07/2024
Actor: Adrien RICQUE
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch

import requests
import os
import base64
from json import dump


def get_information(username, password, cve):
    url = f"https://www.opencve.io/api/cve/" + cve
    payload = {}
    encoded_credentials = login_opencve(username, password)
    headers = {
        'Authorization': f'Basic {encoded_credentials}',
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    print(response.text)
    data = response.json()
    save_in_json(data)
    return data
    
def login_opencve(username, password):
    # Encode the login and password
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return encoded_credentials


def save_in_json(data):
    with open('./data/cve_details.json', 'w') as f:
        dump(data, f, indent=4)

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


def generate_detail_cve_report(username, password, cve):
    report_detail = f"reports/{cve}_details-report.pdf"
    print(report_detail)
    data = get_information(username, password, cve)
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



