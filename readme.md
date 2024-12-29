# PMPFinder - Subdomain and GitHub Dork Finder

This project is a Python script designed to discover subdomains of a given domain and find its GitHub dorks. The results will be saved in a file.

![PMPFinder Screenshot](./images/pmp-photo.png)

## Requirements

To install the required dependencies for the project, follow these steps:

1. Navigate to the project folder.
2. Install the required Python dependencies using the `requirements.txt` file by running the following command:

   ```bash
   pip install -r requirements.txt
   ```

### Additional Tools

This script requires additional tools for subdomain discovery and GitHub dork search:

- **httprobe** and **amass** need to be installed.

## Usage

To use the script, run the following command in your terminal:

    ```bash
    python pmpfinder.py example.com
    ```

Replace `example.com` with the domain you want to discover subdomains and GitHub dorks for. The script will find the subdomains and GitHub dorks of the specified domain and save them to the specified file.

## Output

When the script runs, the following output files will be created:

    ```
    <domain>_subdomains.txt
    <domain>http_subdomains.txt
    <domain>_github_dorks.txt
    ```

These files will contain the discovered subdomains and GitHub dorks for the domain.
