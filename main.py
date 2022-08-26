import json
import sys


class Vulnerability:
    def __init__(self, vulnerability_id, vulnerability_severity):
        self.id = vulnerability_id
        self.severity = vulnerability_severity
        self.packages = []

    def add_package(self, pkgName):
        if pkgName not in self.packages:
            self.packages.append(pkgName)

    def __str__(self):
        return f"{self.id}, {self.severity}, {' '.join(self.packages)}"


vulnerabilities = dict()


def load_report(report_name):
    with open(report_name, "r") as f:
        return json.load(f)


def get_vulnerability(id, severity):
    if id not in vulnerabilities.keys():
        vulnerabilities[id] = Vulnerability(id, severity)
    return vulnerabilities[id]


def process_results(results):
    for result in results:
        if "Vulnerabilities" not in result.keys():
            continue
        vulns = result["Vulnerabilities"]
        for vuln in vulns:
            v = get_vulnerability(vuln["VulnerabilityID"], vuln["Severity"])
            v.add_package(vuln["PkgName"])


def sort_vulnerabilities():
    critical = []
    high = []
    medium = []
    low = []
    unknown = []
    for v in vulnerabilities.values():
        if v.severity == "CRITICAL":
            critical.append(v)
        elif v.severity == "HIGH":
            high.append(v)
        elif v.severity == "MEDIUM":
            medium.append(v)
        elif v.severity == "LOW":
            low.append(v)
        else:
            unknown.append(v)
    return critical + high + medium + low + unknown

def process_json_report(report_to_parse):
    vulnerabilities.clear()
    data = load_report(report_to_parse)
    data_results = data["Results"]
    process_results(data_results)
    vulns_sorted = sort_vulnerabilities()
    with open(f'{report_to_parse}.csv', 'w') as output_file:
        for v in vulns_sorted:
            output_file.write(f'{str(v)}\n')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [trivy_json_report]")
        exit(0)
    for i in range(1, len(sys.argv)):
        process_json_report(sys.argv[i])
