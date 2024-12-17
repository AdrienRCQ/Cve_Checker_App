"""
Author: Adrien RICQUE
Version: 1.3
Creation Date: 23/07/2024

Update Date: 29/07/2024
Actor: Adrien RICQUE

"""

import os
from datetime import date
from extract_infos import extract_cve_id, extract_cvss_v3_scores, extract_update_dates


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

    create_document(technology, number, cve_id, cvss, update_date)


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

    create_document(technology, number, cve_id, cvss, update_date)


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
    create_document(technology, number, cve_id, cvss, update_date)


def create_document(techno, number, cve_id, cvss, update_date):
    # Create a filename for the output file
    actual_date = date.today().strftime("%Y_%m_%d")
    report_name = f"./reports/Report-{actual_date}-{techno}.txt"
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


