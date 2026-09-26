"""Legacy reporting module — deliberately vulnerable, for demo purposes."""

import os
import subprocess


def export_report(report_name: str) -> None:
    # Seeded flaw: shell command built from user input.
    os.system("convert /tmp/report_%s.pdf" % report_name)


def run_backup(table: str) -> None:
    subprocess.call("pg_dump " + table, shell=True)
