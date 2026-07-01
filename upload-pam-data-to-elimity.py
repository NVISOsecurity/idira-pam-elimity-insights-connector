import requests
import sys
import logging

from pathlib import Path
from fnmatch import fnmatchcase
from datetime import datetime
from dotenv import load_dotenv
from os import getenv, environ
from pprint import pformat
from typing import List
from logging.handlers import RotatingFileHandler

from elimity_insights_client import (
    AttributeAssignment,
    BooleanValue,
    Client,
    Config,
    DateTime,
    DateTimeValue,
    DomainGraph,
    Entity,
    NumberValue,
    Relationship,
    StringValue,
)

# Timeout (in seconds) for all HTTP requests to avoid hanging indefinitely
REQUEST_TIMEOUT = 60

logger = logging.getLogger(__name__)


def _safe_fromtimestamp(value, divisor=1) -> DateTimeValue | None:
    """Convert a numeric timestamp (or numeric-string) into Elimity DateTimeValue safely.
    Returns None if the value is missing or invalid.
    """
    if value is None:
        return None
    try:
        # Allow strings that contain numbers
        timestamp_in_seconds = float(value) / divisor
    except Exception:
        return None
    try:
        dt = datetime.fromtimestamp(timestamp_in_seconds)

        return DateTimeValue(
            DateTime(
                year=dt.year,
                month=dt.month,
                day=dt.day,
                hour=dt.hour,
                minute=dt.minute,
                second=dt.second,
            )
        )
    except Exception:
        return None


def _matches_any_pattern(value: str, patterns: List[str]) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def get_required_env_vars(*var_names):
    """Retrieve environment variables by name, and return them as a tuple in the same order as var_names.
    Raises a ValueError if any of the required environment variables is not defined.
    """
    values = []
    for var in var_names:
        value = getenv(var)
        logger.debug("get_required_env_vars: Loading environment variable - '%s'", var)
        if value is None:
            raise ValueError(f"Required environment variable '{var}' is not defined.")
        values.append(value)
    return tuple(values)


def authenticate(env_type, api_base, username, password, verify_ssl=True):
    """Authenticate to PVWA or Identity API and return the session token."""
    # If the target PAM environment is PrivCloud ISPSS, get session token via Identity tenant
    if env_type == "PRIVCLOUD_ISPSS":
        auth_url = f"https://{api_base}.id.cyberark.cloud/oauth2/platformtoken"
        url_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        url_params = {
            "grant_type": "client_credentials",
            "client_id": username,
            "client_secret": password,
        }
        response = requests.post(
            auth_url,
            headers=url_headers,
            data=url_params,
            verify=verify_ssl,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        logger.debug(
            "PrivCloud ISPSS Authentication API response: status=%s, len=%d",
            response.status_code,
            len(response.text or ""),
        )

        return response.json()["access_token"].strip('"')

    # If the target PAM environment is PAM Self-Hosted, get the session token via the CyberArk Vault authentication method
    if env_type == "PAM_SELFHOSTED":
        auth_url = f"{api_base}/api/auth/CyberArk/Logon"
        auth_data = {
            "username": username,
            "password": password,
        }
        response = requests.post(auth_url, json=auth_data, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        logger.debug(
            "PAM Self-Hosted Authentication API response: status=%s, len=%d",
            response.status_code,
            len(response.text or ""),
        )
        return response.text.strip('"')

    logger.error(f"Environment type {env_type} not supported!")
    sys.exit(1)


def logoff(env_type, api_base, session_token, verify_ssl=True):
    """Log off from PVWA."""
    # If the target PAM environment is PrivCloud ISPSS, do nothing
    if env_type == "PRIVCLOUD_ISPSS":
        logger.debug("PrivCloud ISPSS does not seem to have a documented 'Logoff' function - doing nothing.")
        # ISPSS does not seem to have a dedicated "log out my session" functionality (since the session tokens expire after 15 minutes by default), so nothing is implemented here.
        return

    # If the target PAM environment is PAM Self-Hosted, log off via the dedicated API method
    if env_type == "PAM_SELFHOSTED":
        auth_url = f"{api_base}/api/auth/Logoff"
        headers = {
            "Authorization": f"{session_token}",
        }
        response = requests.post(auth_url, headers=headers, verify=verify_ssl, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        logger.debug(
            "PAM Self-Hosted Logoff API response: status=%s, len=%d",
            response.status_code,
            len(response.text or ""),
        )
        return

    return


def get_platforms(pvwa_url, session_token, verify_ssl=True):
    """Retrieve all platforms and return them as a list."""
    headers = {
        "Authorization": f"{session_token}",
    }

    response = requests.get(
        f"{pvwa_url}/api/platforms",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    logger.debug(
        "Get Platforms API response: status=%s, len=%d",
        response.status_code,
        len(response.text or ""),
    )

    return response.json()["Platforms"]


def get_safes(pvwa_url, session_token, verify_ssl=True):
    """Retrieve all safes and return them as a list."""
    batch_size: int = 100
    next_link: str = f"api/Safes?limit={batch_size}&offset=0&useCache=False"
    safes_list: List = []

    headers = {
        "Authorization": f"{session_token}",
    }

    while True:
        response = requests.get(
            f"{pvwa_url}/{next_link}",
            headers=headers,
            verify=verify_ssl,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        logger.debug(
            "Get Safes API response: status=%s, len=%d",
            response.status_code,
            len(response.text or ""),
        )
        safes_list = safes_list + response.json().get("value", [])

        if "nextLink" in response.json():
            next_link = response.json()["nextLink"]
        else:
            break

    return safes_list


def get_safe_members(pvwa_url, session_token, safeUrlId, verify_ssl=True):
    """Retrieve all safe members of a given safe and return them as a list."""
    headers = {
        "Authorization": f"{session_token}",
    }
    response = requests.get(
        f"{pvwa_url}/api/Safes/{safeUrlId}/Members?filter=includePredefinedUsers eq true",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    logger.debug(
        "Get Safe Members API response: status=%s, len=%d",
        response.status_code,
        len(response.text or ""),
    )
    return response.json()["value"]


def get_accounts_per_safe(pvwa_url, session_token, env_type, safeUrlId, verify_ssl=True):
    """Get all accounts in a given safe and return them as a list."""
    logger.debug("get_accounts_per_safe: safeUrlId = %s", safeUrlId)
    batch_size: int = 100

    if env_type == "PRIVCLOUD_ISPSS":
        # If the target PAM environment is PrivCloud ISPSS, use the safeUrlId parameter as is
        # This is because PrivCloud ISPSS as of the latest version (14.6) handles safes
        #  with spaces in the name fine like this, but *not* if the safeUrlId parameter
        #  is double-quoted.
        next_link: str = f"api/accounts?limit={batch_size}&filter=safeName eq {safeUrlId}"

    elif env_type == "PAM_SELFHOSTED":
        # If the target PAM environment is PAM Self-Hosted, wrap the safeUrlId parameter in double quotes
        # This is because PAM Self-Hosted as of the latest version (14.4.3) only handles safes
        #  with spaces in the name correctly when double-quoted, but *not* if the safeUrlId is
        #  specified as is.
        next_link: str = f'api/accounts?limit={batch_size}&filter=safeName eq "{safeUrlId}"'
    else:
        logger.error(f"Environment type {env_type} not supported!")
        sys.exit(1)

    accounts_list: List = []

    headers = {
        "Authorization": f"{session_token}",
    }

    while True:
        logger.debug("get_accounts_per_safe: Sending request")
        logger.debug("get_accounts_per_safe: URL = %s/%s", pvwa_url, next_link)
        logger.debug("get_accounts_per_safe: headers present")
        logger.debug("get_accounts_per_safe: verify = %s", verify_ssl)

        response = requests.get(
            f"{pvwa_url}/{next_link}",
            headers=headers,
            verify=verify_ssl,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        logger.debug(
            "get_accounts_per_safe: Get Accounts API response: status=%s, len=%d",
            response.status_code,
            len(response.text or ""),
        )

        accounts_list = accounts_list + response.json().get("value", [])

        if "nextLink" in response.json():
            next_link = response.json()["nextLink"]
        else:
            break

    return accounts_list


def get_extended_account_details(pvwa_url, session_token, accountId, verify_ssl=True):
    """Get extended account details for a given account."""
    logger.debug("get_extended_account_details: accountId = %s", accountId)

    headers = {
        "Authorization": f"{session_token}",
    }

    response = requests.get(
        f"{pvwa_url}/api/extendedaccounts/{accountId}/overview",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code != 200:
        logger.debug(
            "Failed to get Extended Account details for accountId %s, status=%s",
            accountId,
            response.status_code,
        )
        return None

    response.raise_for_status()
    return response.json()


def get_vault_users(pvwa_url, session_token, verify_ssl=True):
    """Get all Vault users and return them as a list."""
    headers = {
        "Authorization": f"{session_token}",
    }
    response = requests.get(
        f"{pvwa_url}/api/Users?ExtendedDetails=true",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 403:
        logger.error("Failed to retrieve Vault user list. Make sure the Vault API user has the 'Audit Users' authorization.")
        sys.exit(1)

    response.raise_for_status()

    logger.debug(
        "Get Users API response: status=%s, len=%d",
        response.status_code,
        len(response.text or ""),
    )
    return response.json()["Users"]


def get_vault_user_details(pvwa_url, session_token, user_id, verify_ssl=True):
    """Get details for a Vault user."""
    headers = {
        "Authorization": f"{session_token}",
    }
    response = requests.get(
        f"{pvwa_url}/api/Users/{user_id}",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    logger.debug(
        "Get Vault User Details API response: status=%s, len=%d",
        response.status_code,
        len(response.text or ""),
    )
    return response.json()


def get_vault_groups(pvwa_url, session_token, verify_ssl=True):
    """Get all Vault groups with members and return them as a list."""
    headers = {
        "Authorization": f"{session_token}",
    }
    response = requests.get(
        f"{pvwa_url}/api/UserGroups?includeMembers=true",
        headers=headers,
        verify=verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 403:
        logger.error("Failed to retrieve Vault groups list. Make sure the Vault API user has the 'Audit Users' authorization.")
        sys.exit(1)

    response.raise_for_status()

    logger.debug(
        "Get Groups API response: status=%s, len=%d",
        response.status_code,
        len(response.text or ""),
    )
    return response.json()["value"]


def get_entity_by_name(name: str, entities: List[Entity]) -> Entity | None:
    """Return the entity with an exact matching name, or None if not found."""
    for entity in entities:
        if entity.name == name:
            return entity
    return None


def parse_log_level(value: str | None) -> int | None:
    """Parse the configured log level and default to INFO."""
    normalized_value = str(value or "INFO").strip().upper()
    supported_levels = {
        "NONE": None,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }
    if normalized_value not in supported_levels:
        logger.warning("Unsupported IDIRA_PAM_LOGFILE_LOG_LEVEL '%s'; defaulting to INFO", value)
        return logging.INFO
    return supported_levels[normalized_value]


def main():
    # Create and configure logger
    logger.setLevel(logging.INFO)

    env_file = Path(".env")

    # Create log handlers
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatters and add them to the handlers
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(console_handler)

    if not env_file.is_file():
        logger.error(
            f"⚠️  Required .env file not found at '{env_file.resolve()}! Rename the provided '.env.example' file to '.env' and fill in the required configuration variables. See the README.md for more details."
        )
        sys.exit(1)

    # Clear config variables from local environment to avoid using a variable that is not defined in the dotfile
    logger.debug("Clearing all environment variables that begin with 'ELIMITY_'")
    [environ.pop(key) for key in list(environ.keys()) if key.startswith("ELIMITY_")]
    logger.debug("Clearing all environment variables that begin with 'IDIRA_PAM_'")
    [environ.pop(key) for key in list(environ.keys()) if key.startswith("IDIRA_PAM_")]

    # Load config variables from dotenv file
    logger.debug("Loading configuration variables from dotfile into environment")
    load_dotenv(dotenv_path=env_file, override=True)

    log_level = parse_log_level(getenv("IDIRA_PAM_LOGFILE_LOG_LEVEL", "INFO"))

    if log_level is None:
        logger.setLevel(logging.INFO)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"logs/{timestamp}.log"
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(log_file, maxBytes=(10 * 1024 * 1024), backupCount=3)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        logger.setLevel(min(logging.INFO, log_level))
        logger.debug("Configured log level to %s", logging.getLevelName(log_level))

    (
        idira_pam_env_type,
        idira_pam_api_base,
        idira_pam_username,
        idira_pam_password,
    ) = get_required_env_vars(
        "IDIRA_PAM_ENV_TYPE",
        "IDIRA_PAM_API_BASE",
        "IDIRA_PAM_USERNAME",
        "IDIRA_PAM_PASSWORD",
    )

    (
        elimity_insights_base_url,
        elimity_upload_api_id,
        elimity_upload_api_secret,
    ) = get_required_env_vars(
        "ELIMITY_INSIGHTS_BASE_URL",
        "ELIMITY_UPLOAD_API_ID",
        "ELIMITY_UPLOAD_API_SECRET",
    )
    elimity_verify_ssl = getenv("ELIMITY_VERIFY_SSL", "True")
    idira_pam_verify_ssl = getenv("IDIRA_PAM_VERIFY_SSL", "True")

    def _str_to_bool(v: str) -> bool:
        """Parse boolean-like environment values."""
        return str(v).strip().lower() in ("1", "true", "yes", "y")

    idira_pam_verify_ssl = _str_to_bool(idira_pam_verify_ssl)
    elimity_verify_ssl = _str_to_bool(elimity_verify_ssl)

    cyberark_safes_to_skip = getenv(
        "IDIRA_PAM_SAFES_TO_SKIP",
        "AccountsFeed*, Notification Engine, PasswordManager*, Pictures, PSM*, PVWA*, SharedAuth_Internal, System, TelemetryConfig, VaultInternal",
    )
    add_combination_attributes = _str_to_bool(getenv("ELIMITY_ADD_COMBINATION_ATTRIBUTES", "False"))
    combination_attribute_value_delimiter = getenv("ELIMITY_COMBINATION_ATTRIBUTE_VALUE_DELIMITER", "_")

    # Authenticate to Idira PAM environment
    session_token = authenticate(
        idira_pam_env_type,
        idira_pam_api_base,
        idira_pam_username,
        idira_pam_password,
        idira_pam_verify_ssl,
    )
    logger.info("✅ Authenticated to Idira PAM environment successfully")

    # Set PVWA URL and Session Token variables depending on the target environment type (PrivCloud ISPSS vs. PAM Self-Hosted)
    if idira_pam_env_type == "PRIVCLOUD_ISPSS":
        logger.debug("Setting PVWA URL and Session Token format to Privilege Cloud ISPSS format")
        pvwa_url: str = f"https://{idira_pam_api_base}.privilegecloud.cyberark.cloud/PasswordVault"
        # Re-format the session token so that PrivCloud recognizes it.
        # The session token format is different between PrivCloud and Self-Hosted PVWA!
        session_token = f"Bearer {session_token}"
    elif idira_pam_env_type == "PAM_SELFHOSTED":
        logger.debug("Setting PVWA URL and Session Token format to PAM Self-Hosted format")
        pvwa_url: str = f"{idira_pam_api_base}"
    else:
        logger.error(f"Environment type {idira_pam_env_type} not supported!")
        sys.exit(1)

    logger.info(f"🤖 Using PAM API URL: {pvwa_url}")

    safes_to_skip_patterns: List[str] = [element.strip() for element in cyberark_safes_to_skip.split(",") if element.strip()]

    logger.debug("Safe skip patterns = %s", safes_to_skip_patterns)

    # Parse additional account properties to retrieve (comma-separated)
    additional_account_properties_env = getenv("IDIRA_PAM_ADDITIONAL_ACCOUNT_PROPERTIES_TO_RETRIEVE", "")
    additional_account_properties: List[str] = [p.strip() for p in additional_account_properties_env.split(",") if p.strip()]

    logger.debug("Additional account properties to retrieve = %s", additional_account_properties)

    # List of all safe permissions that Elimity should parse
    #  "name": The display name of the permissions as it will appear in the Elimity UI
    #  "internal_name": The internal name of the permission as it will be returned by the PVWA / PrivCloud "Get Safe Member" API
    #    Reference: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe%20members%20ws%20-%20list%20safe%20member.htm#Permissionsparameters
    safe_permissions_to_add: List[dict[str, str]] = [
        {"name": "List accounts", "internal_name": "listAccounts"},
        {"name": "Use accounts", "internal_name": "useAccounts"},
        {"name": "Retrieve accounts", "internal_name": "retrieveAccounts"},
        {"name": "Add accounts", "internal_name": "addAccounts"},
        {
            "name": "Update account properties",
            "internal_name": "updateAccountProperties",
        },
        {"name": "Update account content", "internal_name": "updateAccountContent"},
        {
            "name": "Initiate CPM account management operations",
            "internal_name": "initiateCPMAccountManagementOperations",
        },
        {
            "name": "Specify next account content",
            "internal_name": "specifyNextAccountContent",
        },
        {"name": "Rename accounts", "internal_name": "renameAccounts"},
        {"name": "Delete accounts", "internal_name": "deleteAccounts"},
        {"name": "Unlock accounts", "internal_name": "unlockAccounts"},
        {"name": "Manage Safe", "internal_name": "manageSafe"},
        {"name": "View Safe members", "internal_name": "viewSafeMembers"},
        {"name": "Manage Safe members", "internal_name": "manageSafeMembers"},
        {"name": "View audit log", "internal_name": "viewAuditLog"},
        {"name": "Back up Safe", "internal_name": "backupSafe"},
        {
            "name": "Confirm requests - Level 1",
            "internal_name": "requestsAuthorizationLevel1",
        },
        {
            "name": "Confirm requests - Level 2",
            "internal_name": "requestsAuthorizationLevel2",
        },
        {
            "name": "Access Safe without confirmation",
            "internal_name": "accessWithoutConfirmation",
        },
        {"name": "Move accounts/folders", "internal_name": "moveAccountsAndFolders"},
        {"name": "Create folders", "internal_name": "createFolders"},
        {"name": "Delete folders", "internal_name": "deleteFolders"},
    ]

    # List of all vault authorizations that Elimity should parse
    #  "name": The display name of the authorization as it will appear in the Elimity UI
    #  "internal_name": The internal name of the authorization as it will appear in the PVWA / PrivCloud "Get user details" API
    #    Reference: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/get-user-details-v10.htm#Result
    vault_authorizations_to_add: List[dict[str, str]] = [
        {"name": "Add Safes", "internal_name": "AddSafes"},
        {"name": "Audit Users", "internal_name": "AuditUsers"},
        {"name": "Add/Update Users", "internal_name": "AddUpdateUsers"},
        {"name": "Reset Users Passwords", "internal_name": "ResetUsersPasswords"},
        {"name": "Activate Users", "internal_name": "ActivateUsers"},
        {"name": "Add Network Areas", "internal_name": "AddNetworkAreas"},
        {"name": "Manage Directory Mapping", "internal_name": "ManageDirectoryMapping"},
        {
            "name": "Manage Server File Categories",
            "internal_name": "ManageServerFileCategories",
        },
        {"name": "Backup All Safes", "internal_name": "BackupAllSafes"},
        {"name": "Restore All Safes", "internal_name": "RestoreAllSafes"},
    ]

    # Authenticate to Elimity
    config = Config(
        url=f"{elimity_insights_base_url}",
        id=elimity_upload_api_id,
        token=elimity_upload_api_secret,
        verify_ssl=elimity_verify_ssl,
    )
    client = Client(config)
    logger.info("✅ Authenticated to Elimity Insights API successfully")

    vault_user_entities: List[Entity] = []
    vault_group_entities: List[Entity] = []
    vault_authorizations_entities: List[Entity] = []
    safe_permission_entities: List[Entity] = []
    safe_entities: List[Entity] = []
    account_entities: List[Entity] = []
    platform_entities: List[Entity] = []

    vault_user_to_vault_group_relationships: List[Relationship] = []
    vault_user_to_vault_authorization_relationships: List[Relationship] = []
    vault_user_to_safe_permission_relationships: List[Relationship] = []
    vault_group_to_safe_permission_relationships: List[Relationship] = []
    safe_permission_to_safe_relationships: List[Relationship] = []
    safe_to_account_relationships: List[Relationship] = []
    platform_to_account_relationships: List[Relationship] = []

    # Retrieve platforms
    platforms = get_platforms(pvwa_url, session_token, idira_pam_verify_ssl)
    logger.info(f"📑 Retrieved {len(platforms)} Platforms via Idira PAM REST API")
    logger.debug(pformat(platforms))

    # Retrieve safes
    safes = get_safes(pvwa_url, session_token, idira_pam_verify_ssl)
    safes = sorted(safes, key=lambda safe: safe.get("safeName", "").lower())
    logger.info(f"📦 Retrieved {len(safes)} Safes via Idira PAM REST API")
    logger.debug(pformat(safes))

    # Retrieve vault users
    vault_users = get_vault_users(pvwa_url, session_token, idira_pam_verify_ssl)
    logger.info(f"👤 Retrieved {len(vault_users)} Users via Idira PAM REST API")
    logger.debug(pformat(vault_users))

    # Retrieve vault groups
    vault_groups = get_vault_groups(pvwa_url, session_token, idira_pam_verify_ssl)
    logger.info(f"👥 Retrieved {len(vault_groups)} Groups via Idira PAM REST API")
    logger.debug(pformat(vault_groups))

    #######################################################################
    ## Vault Authorizations Loop                                         ##
    #######################################################################

    logger.debug("Creating Vault Authorization entities")

    # This loop creates "Vault Authorization" entities in Elimity (for example for the "Add/Update Users" authorization) that Vault user entities will later
    # be linked to.
    for vault_authz in vault_authorizations_to_add:
        logger.debug(
            "Creating Vault Authorization entity: ID %s, Name %s",
            vault_authz["internal_name"],
            vault_authz["name"],
        )
        vault_authorizations_entities.append(
            Entity(
                id=vault_authz["internal_name"],
                name=vault_authz["name"],
                type="vault_authorization",
                attribute_assignments=[],
            )
        )

    #######################################################################
    ## Platforms Loop                                                    ##
    #######################################################################

    logger.info("🔄 Starting platforms loop")

    for platform in platforms:
        logger.debug("Handling platform name %s, ID %s", platform["general"]["name"], platform["general"]["id"])

        platform_entity_attributes: List[AttributeAssignment] = [
            AttributeAssignment("allow_manual_change", BooleanValue(platform["credentialsManagement"]["allowManualChange"])),
            AttributeAssignment("allow_manual_reconciliation", BooleanValue(platform["credentialsManagement"]["allowManualReconciliation"])),
            AttributeAssignment("allow_manual_verification", BooleanValue(platform["credentialsManagement"]["allowManualVerification"])),
            AttributeAssignment("allowed_safes", StringValue(platform["credentialsManagement"]["allowedSafes"])),
            AttributeAssignment("automatic_reconciliation_when_unsynched", BooleanValue(platform["credentialsManagement"]["automaticReconcileWhenUnsynched"])),
            AttributeAssignment("description", StringValue(platform["general"]["description"])),
            AttributeAssignment("is_active", BooleanValue(platform["general"]["active"])),
            AttributeAssignment("perform_periodic_change", BooleanValue(platform["credentialsManagement"]["performPeriodicChange"])),
            AttributeAssignment("perform_periodic_verification", BooleanValue(platform["credentialsManagement"]["performPeriodicVerification"])),
            AttributeAssignment("require_password_change_every_x_days", NumberValue(platform["credentialsManagement"]["requirePasswordChangeEveryXDays"])),
            AttributeAssignment(
                "require_password_verification_every_x_days", NumberValue(platform["credentialsManagement"]["requirePasswordVerificationEveryXDays"])
            ),
            AttributeAssignment(
                "require_dual_control_password_access_approval",
                BooleanValue(platform.get("privilegedAccessWorkflows", {}).get("requireDualControlPasswordAccessApproval", None)),
            ),
            AttributeAssignment(
                "enforce_checkin_checkout_exclusive_access",
                BooleanValue(platform.get("privilegedAccessWorkflows", {}).get("enforceCheckinCheckoutExclusiveAccess", None)),
            ),
            AttributeAssignment(
                "enforce_one_time_password_access", BooleanValue(platform.get("privilegedAccessWorkflows", {}).get("enforceOnetimePasswordAccess", None))
            ),
            # Using "Title Case" for platform type to make it more readable in Elimity UI (for example, "Regular" instead of "regular")
            AttributeAssignment("platform_type", StringValue(platform["general"]["platformType"].title())),
            AttributeAssignment("psm_server_id", StringValue(platform.get("sessionManagement", {}).get("PSMServerID", None))),
            AttributeAssignment(
                "record_and_save_session_activity", BooleanValue(platform.get("sessionManagement", {}).get("recordAndSaveSessionActivity", None))
            ),
            AttributeAssignment(
                "require_privileged_session_management_and_isolation",
                BooleanValue(platform.get("sessionManagement", {}).get("requirePrivilegedSessionMonitoringAndIsolation", None)),
            ),
        ]

        platform_entities.append(
            Entity(
                id=str(platform["general"]["id"]),
                name=f"{platform['general']['id']}",
                type="platform",
                attribute_assignments=platform_entity_attributes,
            )
        )

    #######################################################################
    ## Vault Users Loop                                                  ##
    #######################################################################

    logger.info("🔄 Starting users loop")

    for user in vault_users:
        logger.debug("Handling user name %s, ID %s", user["username"], user["id"])

        logger.debug("Getting user details for user ID %s", user["id"])
        user_details = get_vault_user_details(
            pvwa_url,
            session_token,
            user["id"],
            idira_pam_verify_ssl,
        )

        vault_user_entity_attributes: List[AttributeAssignment] = [
            AttributeAssignment("first_name", StringValue(user["personalDetails"]["firstName"])),
            AttributeAssignment("middle_name", StringValue(user["personalDetails"]["middleName"])),
            AttributeAssignment("last_name", StringValue(user["personalDetails"]["lastName"])),
            AttributeAssignment("organization", StringValue(user["personalDetails"]["organization"])),
            AttributeAssignment("department", StringValue(user["personalDetails"]["department"])),
            AttributeAssignment("type", StringValue(user["userType"])),
            AttributeAssignment("is_enabled", BooleanValue(user["enableUser"])),
            AttributeAssignment("is_suspended", BooleanValue(user["suspended"])),
            AttributeAssignment("source", StringValue(user["source"])),
            AttributeAssignment("location", StringValue(user["location"])),
            AttributeAssignment("is_component_user", BooleanValue(user["componentUser"])),
            # Extended user details
            AttributeAssignment("password_never_expires", BooleanValue(user_details["passwordNeverExpires"])),
            AttributeAssignment("change_pass_on_next_logon", BooleanValue(user_details["changePassOnNextLogon"])),
            AttributeAssignment("distinguished_name", StringValue(user_details["distinguishedName"])),
            AttributeAssignment("description", StringValue(user_details["description"])),
            AttributeAssignment("business_email", StringValue(user_details["internet"]["businessEmail"])),
        ]

        if (last_logon_time := _safe_fromtimestamp(user_details.get("lastSuccessfulLoginDate"))) is not None:
            vault_user_entity_attributes.append(AttributeAssignment("last_successful_logon", last_logon_time))

        vault_user_entities.append(
            Entity(
                id=str(user["id"]),
                name=f"{user['username']}",
                type="vault_user",
                attribute_assignments=vault_user_entity_attributes,
            )
        )

        for vault_authz in vault_authorizations_to_add:
            if vault_authz["internal_name"] in user["vaultAuthorization"]:
                logger.debug("Linking user %s to Vault Authz %s", user["username"], vault_authz["internal_name"])
                vault_user_to_vault_authorization_relationships.append(
                    Relationship(
                        from_entity_id=str(user["id"]),
                        from_entity_type="vault_user",
                        to_entity_id=vault_authz["internal_name"],
                        to_entity_type="vault_authorization",
                        attribute_assignments=[],
                    )
                )

    #######################################################################
    ## Vault Groups Loop                                                 ##
    #######################################################################

    logger.info("🔄 Starting groups loop")

    for group in vault_groups:
        logger.debug("Handling group name %s, ID %s", group["groupName"], group["id"])

        vault_group_entity_attributes: List[AttributeAssignment] = [
            AttributeAssignment("description", StringValue(group["description"])),
            AttributeAssignment("type", StringValue(group["groupType"])),
            AttributeAssignment("location", StringValue(group["location"])),
        ]

        vault_group_entities.append(
            Entity(
                id=str(group["id"]),
                name=f"{group['groupName']}",
                type="vault_group",
                attribute_assignments=vault_group_entity_attributes,
            )
        )

    #######################################################################
    ## Vault Groups to Users Loop                                        ##
    #######################################################################
    logger.info("🔄 Starting groups->users loop")

    for group in vault_groups:
        logger.debug("Handling group name %s, ID %s", group["groupName"], group["id"])

        for group_member in group["members"]:
            logger.debug("Handling member ID %s", group_member["id"])

            # Check if the group member already exists in the vault_user_entities list - if
            #   not, add it. The match is done base on the principal name (username or group
            #   name). Logically, it *should* be done based on the principal ID (user id or
            #   group id), but in PrivCloud that leads to some users being added twice.
            #   This is because the PrivCloud APIs present the same user with different IDs
            #   based on the context - for example, in the "Get Users" PrivCloud API output,
            #   the user with the name "X" can be shown with ID 10, but in the "Get Safe Details"
            #   PrivCloud API output for a given safe, the safe creator will be listed as the
            #   user with the name "X", and the ID 1a2b.

            matching_user = get_entity_by_name(group_member["username"], vault_user_entities)

            if matching_user is None:
                # Group member does not exist in vault_users list
                logger.debug(
                    "Group member ID %s Name %s does not exist in Vault User Entities list, adding it to list",
                    group_member["id"],
                    group_member["username"],
                )

                matching_user = Entity(
                    id=str(group_member["id"]),
                    name=str(group_member["username"]),
                    type="vault_user",
                    attribute_assignments=[],
                )

                vault_user_entities.append(matching_user)

            # Group member now definitely exists in the vault_users list. Adding link between vault_user and vault_group entities.
            logger.debug("Adding User->Group relationship: Group Member User ID %s --> Group ID %s", matching_user.id, group["id"])
            vault_user_to_vault_group_relationships.append(
                Relationship(
                    from_entity_id=str(matching_user.id),
                    from_entity_type="vault_user",
                    to_entity_id=str(group["id"]),
                    to_entity_type="vault_group",
                    attribute_assignments=[],
                )
            )

    #######################################################################
    ## Safe Loop                                                         ##
    #######################################################################

    logger.info("🔄 Starting safes loop")
    for safe in safes:
        logger.debug("Handling safe name %s", safe["safeName"])
        # Skip processing this safe if the name matches any configured pattern.
        if _matches_any_pattern(safe["safeName"], safes_to_skip_patterns):
            logger.info(f"  ⏩ {safe['safeName']:<30}[skipped]")
            logger.debug("Safe %s matched 'IDIRA_PAM_SAFES_TO_SKIP' pattern list - skipping", safe["safeName"])
            continue

        logger.info(f"  🗃️  {safe['safeName']}")
        logger.debug("Creating safe permissions entities for safe: %s", safe["safeName"])

        # This loop creates safe-specific "Safe Permission" entities in Elimity
        # (for example for the "List Accounts" permission) that Vault Users or
        # Groups will later be linked to, if they have that specific permission
        # on that specific safe.
        for safe_permission in safe_permissions_to_add:
            logger.debug("Creating Safe Permission entity: ID %s on Safe Name %s", safe_permission["internal_name"], safe["safeName"])

            safe_permission_attribute_assignments: List[AttributeAssignment] = [
                AttributeAssignment("safe_name", StringValue(safe["safeName"])),
                AttributeAssignment("safe_permission_type", StringValue(safe_permission["name"])),
            ]

            safe_permission_entities.append(
                Entity(
                    id=f"{safe['safeNumber']}_{safe_permission['internal_name']}",
                    name=f"{safe['safeName']} - {safe_permission['name']}",
                    type="safe_permission",
                    attribute_assignments=safe_permission_attribute_assignments,
                )
            )

            logger.debug("Linking Safe Permission to Safe: ID %s --> Safe Name %s", safe_permission["internal_name"], safe["safeName"])

            safe_permission_to_safe_relationships.append(
                Relationship(
                    from_entity_id=f"{safe['safeNumber']}_{safe_permission['internal_name']}",
                    from_entity_type="safe_permission",
                    to_entity_id=str(safe["safeNumber"]),
                    to_entity_type="safe",
                    attribute_assignments=[],
                )
            )
        # End of Safe Permission entity creation loop

        # If the Safe Creator User is not already in the vault_users list, add it.
        # This can happen in PrivCloud environments, because the PrivCloud Auditor
        #   permissions allows Elimity to see all safes, but not all users.
        # It can also happen in PAM Self-Hosted environments if the Elimity user is
        #   in a lower / different Vault location than the safe owner.
        # Meaning, Elimity could see safes with a safe creator ID / safe creator name
        #   property set, but that user does not appear in the vault users list.
        # In this case, we need to add that user to the vault users entities list
        #   (but without user details like first name, last name, email, enable status,
        #   authorizations; because we can't see those)
        logger.debug("Checking if safe creator exists in vault users list - creator user id: %s", safe["creator"]["name"])

        matching_principal = get_entity_by_name(safe["creator"]["name"], vault_user_entities)

        if matching_principal is None:
            logger.debug("User does not exist, adding to vault_users list - safe creator user name: %s", safe["creator"]["name"])
            safe_creator_attribute_assignments: List[AttributeAssignment] = []

            matching_principal = Entity(
                id=str(safe["creator"]["id"]),
                name=safe["creator"]["name"],
                type="vault_user",
                attribute_assignments=safe_creator_attribute_assignments,
            )

            vault_user_entities.append(matching_principal)

        safe_entity_attributes: List[AttributeAssignment] = [
            AttributeAssignment("created_by_internal_user_id", StringValue(safe["creator"]["id"])),
            AttributeAssignment("created_by_name", StringValue(safe["creator"]["name"])),
            AttributeAssignment("description", StringValue(safe["description"])),
            AttributeAssignment("auto_purge_enabled", BooleanValue(safe["autoPurgeEnabled"])),
            AttributeAssignment("managing_cpm", StringValue(safe["managingCPM"])),
            AttributeAssignment("number_of_days_retention", NumberValue(safe["numberOfDaysRetention"])),
            AttributeAssignment(
                "number_of_versions_retention",
                NumberValue(safe["numberOfVersionsRetention"]),
            ),
            AttributeAssignment("olac_enabled", BooleanValue(safe["olacEnabled"])),
        ]

        if (safe_creation_datetime := _safe_fromtimestamp(safe.get("creationTime"))) is not None:
            safe_entity_attributes.append(AttributeAssignment("creation_datetime", safe_creation_datetime))

        # As of PrivCloud v14.8, the lastModificationTime safe property is returned by the API in microsecond precision, and not second precision as all of the
        # other timestamps
        if (safe_last_modification_datetime := _safe_fromtimestamp(safe.get("lastModificationTime"), divisor=1000000)) is not None:
            safe_entity_attributes.append(AttributeAssignment("last_modification_datetime", safe_last_modification_datetime))

        safe_entities.append(
            Entity(
                id=str(safe["safeNumber"]),
                name=safe["safeName"],
                type="safe",
                attribute_assignments=safe_entity_attributes,
            )
        )

        #######################################################################
        ## Safe Member Loop                                                  ##
        #######################################################################

        logger.debug("Handling safe members of safe %s", safe["safeName"])

        # Get Safe Members per Safe
        safe_members = get_safe_members(pvwa_url, session_token, safe["safeUrlId"], idira_pam_verify_ssl)

        logger.debug("Safe Members of Safe %s = %s", safe["safeName"], pformat(safe_members))
        for safeMember in safe_members:
            logger.debug("Processing Safe Member: %s", safeMember["memberName"])

            if safeMember["memberType"] == "User":
                # Check if a user with the same name as the safe member
                #   exists in the vault_users list already - if not, add it.
                matching_principal = get_entity_by_name(safeMember["memberName"], vault_user_entities)

                if matching_principal is None:
                    logger.debug(
                        "User does not exist, adding to vault_users list - safeMember ID: %s, Name %s",
                        safeMember["memberId"],
                        safeMember["memberName"],
                    )
                    safe_creator_attribute_assignments: List[AttributeAssignment] = []

                    matching_principal = Entity(
                        id=str(safeMember["memberId"]),
                        name=safeMember["memberName"],
                        type="vault_user",
                        attribute_assignments=safe_creator_attribute_assignments,
                    )

                    vault_user_entities.append(matching_principal)

                # Safe member user now definitely exists
                vault_user_to_permission_relationship_attributes: List[AttributeAssignment] = [
                    AttributeAssignment(
                        "has_expiration_date",
                        BooleanValue(safeMember["isExpiredMembershipEnable"]),
                    ),
                ]

                if safeMember["isExpiredMembershipEnable"]:
                    if (safe_member_membership_expiration_date := _safe_fromtimestamp(safe.get("membershipExpirationDate"))) is not None:
                        vault_user_to_permission_relationship_attributes.append(AttributeAssignment("expiration_date", safe_member_membership_expiration_date))

                for safe_permission in safe_permissions_to_add:
                    logger.debug("Handling Safe Permission %s on Safe Member %s", safe_permission["internal_name"], safeMember["memberName"])
                    # Check if the current safe member has a certain permission on the current safe
                    if safeMember["permissions"][safe_permission["internal_name"]] is True:
                        logger.debug(
                            "Safe Permission %s on Safe Member %s is True for Safe Name %s",
                            safe_permission["internal_name"],
                            safeMember["memberName"],
                            safe["safeName"],
                        )
                        # If yes, add a link between the vault user and the safe permission
                        #   entities, but use the ID of the found user as the user
                        #   entity ID, instead of the ID supplied by the "Get Members" API.
                        # This is so that we link the safe permission to an existing vault user
                        #   object instead of a non-existing one.
                        vault_user_to_safe_permission_relationships.append(
                            Relationship(
                                from_entity_id=matching_principal.id,
                                from_entity_type="vault_user",
                                to_entity_id=f"{safe['safeNumber']}_{safe_permission['internal_name']}",
                                to_entity_type="safe_permission",
                                attribute_assignments=vault_user_to_permission_relationship_attributes,
                            )
                        )
                    else:
                        logger.debug(
                            "Safe Permission %s on Safe Member %s is False for Safe Name %s",
                            safe_permission["internal_name"],
                            safeMember["memberName"],
                            safe["safeName"],
                        )

            if safeMember["memberType"] == "Group":
                # Check if a group with the same name as the safe member
                #   exists in the vault_groups list already - if not, add it.
                matching_principal = get_entity_by_name(safeMember["memberName"], vault_group_entities)

                if matching_principal is None:
                    logger.debug(
                        "Group does not exist, adding to vault_groups list - safeMember ID: %s, Name %s",
                        safeMember["memberId"],
                        safeMember["memberName"],
                    )
                    safe_creator_attribute_assignments: List[AttributeAssignment] = []

                    matching_principal = Entity(
                        id=str(safeMember["memberId"]),
                        name=safeMember["memberName"],
                        type="vault_group",
                        attribute_assignments=safe_creator_attribute_assignments,
                    )

                    vault_group_entities.append(matching_principal)

                # Safe member group now definitely exists
                vault_group_to_permission_relationship_attributes: List[AttributeAssignment] = [
                    AttributeAssignment(
                        "has_expiration_date",
                        BooleanValue(safeMember["isExpiredMembershipEnable"]),
                    ),
                ]

                if safeMember["isExpiredMembershipEnable"]:
                    if (safe_member_membership_expiration_date := _safe_fromtimestamp(safe.get("membershipExpirationDate"))) is not None:
                        vault_group_to_permission_relationship_attributes.append(AttributeAssignment("expiration_date", safe_member_membership_expiration_date))

                for safe_permission in safe_permissions_to_add:
                    logger.debug("Handling Safe Permission %s on Safe Member %s", safe_permission["internal_name"], safeMember["memberName"])
                    # Check if the current safe member has a certain permission on the current safe
                    if safeMember["permissions"][safe_permission["internal_name"]] is True:
                        logger.debug(
                            "Safe Permission %s on Safe Member %s is True for Safe Name %s",
                            safe_permission["internal_name"],
                            safeMember["memberName"],
                            safe["safeName"],
                        )
                        # If yes, add a link between the vault group and the safe permission
                        #   entities, but use the ID of the found group as the group
                        #   entity ID, instead of the ID supplied by the "Get Members" API.
                        # This is so that we link the safe permission to an existing vault_group
                        #   object instead of a non-existing one.
                        vault_group_to_safe_permission_relationships.append(
                            Relationship(
                                from_entity_id=matching_principal.id,
                                from_entity_type="vault_group",
                                to_entity_id=f"{safe['safeNumber']}_{safe_permission['internal_name']}",
                                to_entity_type="safe_permission",
                                attribute_assignments=vault_group_to_permission_relationship_attributes,
                            )
                        )
                    else:
                        logger.debug(
                            "Safe Permission %s on Safe Member %s is False for Safe Name %s",
                            safe_permission["internal_name"],
                            safeMember["memberName"],
                            safe["safeName"],
                        )
            # End safe permission loop
        # End safe member loop

        #######################################################################
        ## Accounts Loop                                                     ##
        #######################################################################

        logger.debug("Handling accounts in safe %s", safe["safeName"])

        accounts = get_accounts_per_safe(
            pvwa_url,
            session_token,
            idira_pam_env_type,
            safe["safeUrlId"],
            idira_pam_verify_ssl,
        )

        logger.debug("Accounts in Safe %s = %s", safe["safeName"], pformat(accounts))

        for account in accounts:
            logger.debug(
                "Processing Account: %s on %s",
                account.get("userName", "<EMPTY_USERNAME>"),
                account.get("address", "<EMPTY_ADDRESS>"),
            )

            account_entity_attributes: List[AttributeAssignment] = [
                AttributeAssignment("username", StringValue(account.get("userName", ""))),
                AttributeAssignment("safe_name", StringValue(account["safeName"])),
                AttributeAssignment("address", StringValue(account.get("address", ""))),
                AttributeAssignment("platform_id", StringValue(account.get("platformId", ""))),
                AttributeAssignment(
                    "logon_domain",
                    StringValue(account.get("platformAccountProperties", {}).get("LogonDomain", "")),
                ),
                AttributeAssignment(
                    "status",
                    StringValue(account.get("secretManagement", {}).get("status", "Unknown")),
                ),
                AttributeAssignment(
                    "automatic_management_is_enabled",
                    BooleanValue(account.get("secretManagement", {}).get("automaticManagementEnabled", "Unknown")),
                ),
            ]

            # Retrieve additional account properties (which are not always present), as defined by the "IDIRA_PAM_ADDITIONAL_ACCOUNT_PROPERTIES_TO_RETRIEVE"
            # environment variable, and add them as entity attributes
            for account_property_name in additional_account_properties:
                val = account.get("platformAccountProperties", {}).get(account_property_name, "")
                account_entity_attributes.append(AttributeAssignment(account_property_name.lower(), StringValue(val)))

            timestamp_properties_to_add = [
                {"account_property_name": "lastModifiedTime", "elimity_entity_attribute_name": "last_modified_time"},
                {"account_property_name": "lastReconciledTime", "elimity_entity_attribute_name": "last_reconciled_time"},
                {"account_property_name": "lastVerifiedTime", "elimity_entity_attribute_name": "last_verified_time"},
            ]

            for timestamp_property in timestamp_properties_to_add:
                # If the account has the property set, add it as an entity attribute
                if account.get("secretManagement", {}).get(timestamp_property["account_property_name"], False):
                    if (timestamp := _safe_fromtimestamp(account.get("secretManagement", {}).get(timestamp_property["account_property_name"], ""))) is not None:
                        account_entity_attributes.append(AttributeAssignment(timestamp_property["elimity_entity_attribute_name"], timestamp))

            extended_account_details = get_extended_account_details(
                pvwa_url,
                session_token,
                account["id"],
                idira_pam_verify_ssl,
            )

            if extended_account_details:
                account_entity_attributes = account_entity_attributes + [
                    AttributeAssignment("compliance_is_compliant", BooleanValue(extended_account_details.get("Compliance", {}).get("IsCompliant", None))),
                    AttributeAssignment("last_modified_by", StringValue(extended_account_details.get("Compliance", {}).get("LastModifiedBy", None))),
                    AttributeAssignment("last_modification_type", StringValue(extended_account_details.get("Compliance", {}).get("ModificationType", None))),
                    AttributeAssignment("cpm_disable_reason", StringValue(extended_account_details.get("Details", {}).get("CPMDisabled", None))),
                    AttributeAssignment("cpm_status", StringValue(extended_account_details.get("Details", {}).get("CPMStatus", None))),
                    AttributeAssignment("cpm_error_details", StringValue(extended_account_details.get("Details", {}).get("CPMErrorDetails", None))),
                    AttributeAssignment("deleted_by", StringValue(extended_account_details.get("Details", {}).get("DeletedBy", None))),
                    AttributeAssignment("dual_control_status", StringValue(extended_account_details.get("Details", {}).get("DualControlStatus", None))),
                ]

                # If the account has the DeletionDate set, add it as an entity attribute
                if extended_account_details.get("Details", {}).get("DeletionDate", None):
                    if (timestamp := _safe_fromtimestamp(extended_account_details.get("Details", {}).get("DeletionDate", None))) is not None:
                        account_entity_attributes.append(AttributeAssignment("deletion_date", timestamp))
            # End extended account details section

            # Add combination attributes if enabled
            if add_combination_attributes:
                account_entity_attributes.append(
                    AttributeAssignment(
                        "comb_username_address",
                        StringValue(
                            f"{account.get('userName', '<EMPTY_USERNAME>')}{combination_attribute_value_delimiter}{account.get('address', '<EMPTY_ADDRESS>')}"
                        ),
                    )
                )
                account_entity_attributes.append(
                    AttributeAssignment(
                        "comb_username_address_logondomain",
                        StringValue(
                            f"{account.get('userName', '<EMPTY_USERNAME>')}{combination_attribute_value_delimiter}{account.get('address', '<EMPTY_ADDRESS>')}{combination_attribute_value_delimiter}{account.get('logonDomain', '<EMPTY_LOGON_DOMAIN>')}"
                        ),
                    )
                )
                account_entity_attributes.append(
                    AttributeAssignment(
                        "comb_username_address_platform",
                        StringValue(
                            f"{account.get('userName', '<EMPTY_USERNAME>')}{combination_attribute_value_delimiter}{account.get('address', '<EMPTY_ADDRESS>')}{combination_attribute_value_delimiter}{account.get('platformId', '<EMPTY_PLATFORM_ID>')}"
                        ),
                    )
                )
            # End combination attributes section

            account_entities.append(
                Entity(
                    id=str(account["id"]),
                    name=f"{account.get('userName', '<EMPTY_USERNAME>')} on {account.get('address', '<EMPTY_ADDRESS>')}",
                    type="account",
                    attribute_assignments=account_entity_attributes,
                )
            )

            safe_to_account_relationship_attributes: List[AttributeAssignment] = []
            safe_to_account_relationships.append(
                Relationship(
                    from_entity_id=str(safe["safeNumber"]),
                    from_entity_type="safe",
                    to_entity_id=str(account["id"]),
                    to_entity_type="account",
                    attribute_assignments=safe_to_account_relationship_attributes,
                )
            )

            if account["platformId"]:
                logger.debug("Linking accountId %s to platformId %s", account["id"], account["platformId"])

                platform_to_account_relationship_attributes: List[AttributeAssignment] = []
                platform_to_account_relationships.append(
                    Relationship(
                        from_entity_id=str(account["platformId"]),
                        from_entity_type="platform",
                        to_entity_id=str(account["id"]),
                        to_entity_type="account",
                        attribute_assignments=platform_to_account_relationship_attributes,
                    )
                )
            else:
                logger.debug(
                    "Account accountId %s does not have a platform assigned - not creating a account->platform link",
                    account["id"],
                )
        # End account loop

    # Log off from PVWA
    logoff(idira_pam_env_type, idira_pam_api_base, session_token, idira_pam_verify_ssl)

    #######################################################################
    ## Entity Upload to Elimity                                          ##
    #######################################################################
    logger.info("🔧 Preparing entities for upload")
    logger.info(f"   {len(vault_user_entities):>5} Vault User entities")
    logger.info(f"   {len(vault_group_entities):>5} Vault Group entities")
    logger.info(f"   {len(vault_authorizations_entities):>5} Vault Authorization entities")
    logger.info(f"   {len(safe_permission_entities):>5} Safe Permission entities")
    logger.info(f"   {len(safe_entities):>5} Safe entities")
    logger.info(f"   {len(account_entities):>5} Account entities")
    logger.info(f"   {len(platform_entities):>5} Platform entities")

    entities_to_upload: List[Entity] = (
        platform_entities
        + safe_entities
        + safe_permission_entities
        + account_entities
        + vault_user_entities
        + vault_group_entities
        + vault_authorizations_entities
    )

    logger.info("🔧 Preparing entity relationships for upload")
    logger.info(f"   {len(vault_user_to_vault_group_relationships):>5} Vault User->Vault Group relationships")
    logger.info(f"   {len(vault_user_to_vault_authorization_relationships):>5} Vault User->Vault Authz relationships")
    logger.info(f"   {len(vault_user_to_safe_permission_relationships):>5} Vault User->Safe Permission relationships")
    logger.info(f"   {len(vault_group_to_safe_permission_relationships):>5} Vault Group->Safe Permission relationships")
    logger.info(f"   {len(safe_permission_to_safe_relationships):>5} Safe Permission->Safe relationships")
    logger.info(f"   {len(safe_to_account_relationships):>5} Safe->Account relationships")
    logger.info(f"   {len(platform_to_account_relationships):>5} Platform->Account relationships")

    relationships_to_upload: List[Relationship] = (
        platform_to_account_relationships
        + safe_to_account_relationships
        + safe_permission_to_safe_relationships
        + vault_user_to_vault_authorization_relationships
        + vault_user_to_vault_group_relationships
        + vault_user_to_safe_permission_relationships
        + vault_group_to_safe_permission_relationships
    )

    logger.debug("Creating domain graph")
    graph = DomainGraph(
        entities=entities_to_upload,
        relationships=relationships_to_upload,
    )

    logger.info("📤 Uploading data to Elimity...")
    client.reload_domain_graph(graph)
    logger.info("Upload to Elimity finished - Check if the import was successful in Elimity > Sources > *Source Name* > Imports")
    logger.info(f"🔗  {elimity_insights_base_url}/administration/sources/{elimity_upload_api_id}")


if __name__ == "__main__":
    main()
