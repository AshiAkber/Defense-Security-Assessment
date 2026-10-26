# Defense Security Assessment Tool

## Aim
To demonstrate basic defensive cybersecurity assessment, authentication log analysis, risk identification, and reporting using Windows and Python 3.

## Features
- Reports Windows operating system information.
- Reports the Python version.
- Provides basic information about execution privileges.
- Recommends reviewing Windows Defender Firewall settings.
- Counts failed authentication events in a supplied log.
- Flags repeated failures for manual review.
- Exports results to a JSON file.

## Requirements
- Windows 10 or Windows 11
- Python 3
- Notepad or another text editor
- No third-party Python packages required

## How to Run

Open Command Prompt and navigate to the project directory:

    cd "%USERPROFILE%\Defense-Security-Assessment"

Run the program:

    python security_assessment.py

Use a different log file:

    python security_assessment.py --log sample_logs/auth.log

Change the review threshold:

    python security_assessment.py --threshold 5

Choose the JSON output file:

    python security_assessment.py --output assessment_report.json

## Expected Sample Result

The fictional sample log contains four failed login events:

- admin: 3
- guest: 1

The default threshold is three failures, so admin is flagged for manual review.

## Output
The program displays assessment findings in Command Prompt and generates `assessment_report.json` in the project directory.

## Limitations and Ethics
This is an educational tool, not a complete security audit. Failed login events do not prove an attack. Windows-specific firewall checks are not performed automatically by this program; review Windows Defender Firewall settings separately. Use only on systems you own or are authorized to assess. Do not publish real logs containing passwords, personal information, or other secrets.
