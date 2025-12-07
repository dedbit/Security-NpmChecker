USAGE INSTRUCTIONS:

1. Download script and instructions to environment that should be scanned
2. Open PowerShell (run as administrator)
3. Run scanner script in desired root folder:
    Example:
        .\Run-ShaiHuludScanner.ps1 "c:\dev"
4. Look at output in PowerShell and in the report stored in ScanReports

---------------------------

TROUBLESHOOTING:

Q: Getting error when running script telling me the script is not digitally signed. How can this be resolved?
A: Try running: Unblock-File -Path "./Run-ShaiHuludScanner.ps1"
or set a more allowing execution policy.

---------------------------

SHARING THIS SCRIPT:

https://orangoab-my.sharepoint.com/:f:/g/personal/mattias_uldin_fellowmind_se/IgC2QYFbTFqlRapfv4gQkBx_AfsrwlT9Ng1u2GahOV85RXA?e=Nnbv4k

---------------------------

CONTACT:

mattias.uldin@fellowmind.se


# Filip Notes

Suspicious packages data source:
https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv

## References

https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/