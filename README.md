# Palo Alto Idira PAM (formerly CyberArk PAM) Elimity Insights Connector

Script to retrieve data from a Idira PAM (formerly CyberArk Privileged Access Manager) environment and upload it to [Elimity Insights](https://elimity.com/)

## PAM environment types

This script reads information from PAM Self-Hosted environments (Vault is hosted in its own VM or server) or Privilege Cloud ISPSS (Palo Alto Idira hosts the PAM environment).
It was tested with PAM Self-Hosted v15.0 and Privilege Cloud ISPSS v14.9.

The *old* PrivCloud "Standard" infrastructure is not supported by this script.

## .env file creation - for providing environment configuration and credentials

Rename the `.env.example` file to `.env`, and uncomment the variables in *either* the "Idira PAM Configuration Variables" section or the "Idira Privilege Cloud Configuration Variables" section.

Fill out the credential information with the user details you created in PAM / PrivCloud and the Elimity source information.

## Prerequisites - Elimity Insights

1. Create a new source in Elimity Insights using the "Custom" preset
2. Import the data model from the `.json` file in the "Elimity-Source-Data-Model" directory.
3. In the source under "Settings", generate API credentials for this source
4. Set the source id and secret in the ".env" file.

## Prerequisites - Idira PAM

Create a user in your PAM environment to read safe, account, platform, user, and group information.
This user must be using password authentication.

### PAM Self-Hosted

1. Create a Vault user with password authentication
2. Give it the "Audit Users" authorization
3. Either
    1. Add it to the "Auditors" group to see all accounts, or
    2. Add it to individual safes with the "List Accounts" permission.
4. Set the URL and API credentials in the ".env" file

### PrivCloud ISPSS

1. Create a user in Identity Admin page with password authentication
2. Enable the "Is OAuth confidential client" property
3. Either
    1. Add it to the "Privilege Cloud Auditors" role, or
    2. Add it to a role to enable PrivCloud login, and add it to individual safes with the "List Accounts" permission.
4. Set the URL and API credentials in the ".env" file

## Run using `uv`

1. Install Python 3 for your system: [Python | Downloads](https://www.python.org/downloads/)
2. Install `uv` for your system: [uv | Installation](https://docs.astral.sh/uv/#installation)
3. Run using `uv`

```shell
uv run upload-pam-data-to-elimity.py
```

## Collected Data

Data collected from the Idira PAM environment:

- Safe details for all safes the Vault API user can see - this includes all safe permission information
- Account properties (except the secret) from all accounts in the safes where the Vault API user has "List Accounts" permission on
- User and group details for all users and groups that the Vault API user can see (based on its location in the Vault location tree) - this includes Idira Identity roles in a PrivCloud environment
- All Vault authorizations and which users/groups are assigned to them
- All platform information and which accounts are assigned to them

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
