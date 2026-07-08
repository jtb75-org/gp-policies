import os
import re
import json
import base64
from datetime import datetime, timezone
import urllib.request
import urllib.error
import boto3
from botocore.exceptions import ClientError

# Read configuration from Lambda environment variables
REGION = os.getenv("AWS_REGION", "us-east-1")
QUARANTINE_BUCKET_NAME = os.getenv("QUARANTINE_BUCKET_NAME")
WIZ_SECRET_NAME = os.getenv("WIZ_SECRET_NAME", "wiz-api-credentials")

# Metadata headers used to store audit information on the quarantined object
ORIGINAL_VERSION_HEADER = "original-version-id"
ORIGINAL_SOURCE_ARN_HEADER = "original-source-arn"
QUARANTINED_AT_HEADER = "quarantined-at"

s3 = boto3.client("s3")
sts = boto3.client("sts")

def _get_quarantine_bucket(account_id):
    """Find or use the configured quarantine bucket."""
    if QUARANTINE_BUCKET_NAME:
        return QUARANTINE_BUCKET_NAME
        
    suffix = f"-wiz-quarantine-{account_id}"
    try:
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            if bucket["Name"].endswith(suffix):
                return bucket["Name"]
    except ClientError as e:
        print(f"[ERROR] Failed to list buckets: {e}")
        raise e
    raise Exception(f"Could not find quarantine bucket ending with {suffix}")


def _parse_s3_resource(resource_id):
    """Parse S3 resource ID."""
    if resource_id.startswith("arn:aws:s3:::"):
        path = resource_id.replace("arn:aws:s3:::", "")
        parts = path.split("/", 1)
        if len(parts) != 2:
            print(f"[WARN] S3 ARN does not contain a key (bucket-only target): {resource_id}")
            return parts[0], None, None
        return parts[0], parts[1], None
    elif "##" in resource_id:
        parts = resource_id.split("##")
        if len(parts) < 3:
            raise ValueError(f"Invalid Wiz S3 composite ID: {resource_id}")
        
        if "-malware-file-discovered-" in parts[2]:
            payload = parts[2]
            sub_parts = payload.split("-malware-file-discovered-")
            bucket = sub_parts[0]
            key = sub_parts[1]
            if key.endswith("-"):
                key = key[:-1]
            return bucket, key, None
        else:
            bucket = parts[0]
            md5 = parts[1]
            key = parts[2]
            return bucket, key, md5
    else:
        raise ValueError(f"Unsupported S3 resource ID format: {resource_id}")


def _find_malicious_version(bucket, key, finding_md5=None):
    """Find the version ID of the object."""
    try:
        versions = s3.list_object_versions(Bucket=bucket, Prefix=key)
    except ClientError as e:
        print(f"[ERROR] Failed to list object versions: {e}")
        raise e

    object_versions = [v for v in versions.get("Versions", []) if v["Key"] == key]
    
    if not object_versions:
        delete_markers = [d for d in versions.get("DeleteMarkers", []) if d["Key"] == key]
        if delete_markers:
            print(f"[WARN] Object {key} already has delete markers, it might have been remediated")
        raise FileNotFoundError(f"No versions found for object {key} in bucket {bucket}")

    if finding_md5:
        target_etag = f'"{finding_md5}"'
        for version in object_versions:
            if version["ETag"] == target_etag:
                print(f"[INFO] Found version matching MD5: {version['VersionId']}")
                return version["VersionId"]
        print(f"[WARN] No version matched MD5 {finding_md5}, defaulting to latest version")

    for version in object_versions:
        if version.get("IsLatest"):
            return version["VersionId"]

    return object_versions[0]["VersionId"]


def _extract_md5_from_finding(finding_data):
    """Try to extract MD5 from finding details."""
    data_str = json.dumps(finding_data) if isinstance(finding_data, (dict, list)) else str(finding_data)
    matches = re.findall(r"\b([a-fA-F0-9]{32})\b", data_str)
    if matches:
        return matches[0].lower()
    return None


def _get_wiz_api_credentials():
    """Retrieve Wiz API Client ID and Secret from AWS Secrets Manager."""
    client = boto3.client('secretsmanager', region_name=REGION)
    try:
        response = client.get_secret_value(SecretId=WIZ_SECRET_NAME)
        if 'SecretString' in response:
            creds = json.loads(response['SecretString'])
            return creds.get('client_id'), creds.get('client_secret')
        raise Exception("Secret string not found in Secrets Manager")
    except Exception as e:
        print(f"[ERROR] Failed to retrieve Wiz API credentials: {e}")
        raise e


def _request_wiz_api_token(client_id, client_secret):
    """Retrieve OAuth token using urllib to avoid heavy requests library layer."""
    auth_payload = f"grant_type=client_credentials&audience=wiz-api&client_id={client_id}&client_secret={client_secret}".encode('utf-8')
    req = urllib.request.Request(
        url="https://auth.app.wiz.io/oauth/token",
        data=auth_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            response_json = json.loads(response.read().decode('utf-8'))
            token = response_json.get('access_token')
            if not token:
                raise ValueError("Access token not found in oauth response")
    except urllib.error.URLError as e:
        print(f"[ERROR] Error authenticating to Wiz Auth: {e}")
        raise e

    # Extract Datacenter code from JWT payload
    payload_part = token.split(".")[1]
    missing_padding = len(payload_part) % 4
    if missing_padding:
        payload_part += "=" * (4 - missing_padding)
    decoded_payload = json.loads(base64.b64decode(payload_part).decode('utf-8'))
    return token, decoded_payload["dc"]


def _query_wiz_api(query, variables, dc, token):
    """Query Wiz API using urllib."""
    data = json.dumps({"variables": variables, "query": query}).encode('utf-8')
    req = urllib.request.Request(
        url=f"https://api.{dc}.app.wiz.io/graphql",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.URLError as e:
        print(f"[ERROR] GraphQL query failed: {e}")
        raise e


def _get_malware_files_for_bucket(bucket_uuid, project_id):
    """Query Wiz API to find all malware instances infecting the bucket UUID."""
    client_id, client_secret = _get_wiz_api_credentials()
    token, dc = _request_wiz_api_token(client_id, client_secret)

    query = """
    query GraphSearch($query: GraphEntityQueryInput!, $projectId: String!, $first: Int) {
      graphSearch(query: $query, projectId: $projectId, first: $first) {
        nodes {
          entities {
            id
            name
            type
            properties
            providerUniqueId
          }
        }
      }
    }
    """

    variables = {
        "projectId": project_id,
        "first": 100,
        "query": {
            "select": True,
            "type": ["BUCKET"],
            "where": {
                "_vertexID": {
                    "EQUALS": [bucket_uuid]
                }
            },
            "relationships": [
                {
                    "type": [
                        {
                            "type": "INFECTS",
                            "reverse": True
                        }
                    ],
                    "with": {
                        "type": ["MALWARE_INSTANCE"],
                        "select": True
                    }
                }
            ]
        }
    }

    result = _query_wiz_api(query, variables, dc, token)
    matches = result.get('data', {}).get('graphSearch', {}).get('nodes', [])
    print(f"[INFO] Wiz Graph Search returned {len(matches)} matches")

    malware_files = []
    for match in matches:
        for entity in match.get('entities', []):
            if entity.get('type') == 'MALWARE_INSTANCE':
                provider_id = entity.get('providerUniqueId') or ''
                properties = entity.get('properties', {})
                
                file_key = None
                if provider_id.startswith('arn:aws:s3:::'):
                    parts = provider_id.split('/', 1)
                    if len(parts) > 1:
                        file_key = parts[1]
                
                if not file_key:
                    file_key = properties.get('path') or properties.get('filePath') or entity.get('name')

                file_md5 = properties.get('fileHash') or properties.get('md5')
                
                if file_key:
                    malware_files.append({
                        "key": file_key,
                        "md5": file_md5
                    })
                    print(f"[INFO] Identified malware file: {file_key} (MD5: {file_md5})")

    return malware_files


def _add_issue_comment(issue_id, comment_text):
    """Add a comment/note to the Wiz Issue detailing the remediation result."""
    if not issue_id:
        print("[INFO] No Issue ID provided in event. Skipping feedback comment.")
        return
        
    print(f"[INFO] Writing feedback comment to Wiz Issue: {issue_id}")
    try:
        client_id, client_secret = _get_wiz_api_credentials()
        token, dc = _request_wiz_api_token(client_id, client_secret)
        
        mutation = """
        mutation CreateIssueComment($input: CreateIssueNoteInput!) {
          createIssueNote(input: $input) {
            issueNote {
              id
              createdAt
            }
          }
        }
        """
        
        variables = {
            "input": {
                "issueId": issue_id,
                "text": comment_text
            }
        }
        
        response = _query_wiz_api(mutation, variables, dc, token)
        if "errors" in response:
            print(f"[WARN] GraphQL errors returned when adding comment: {json.dumps(response['errors'])}")
        else:
            note_id = response.get("data", {}).get("createIssueNote", {}).get("issueNote", {}).get("id")
            print(f"[INFO] Successfully added comment to Wiz Issue. Note ID: {note_id}")
    except Exception as e:
        print(f"[WARN] Failed to write comment back to Wiz Issue: {e}")


def _update_issue_status(issue_id, status):
    """Update the status of the Wiz Issue (e.g. to IN_PROGRESS)."""
    if not issue_id:
        print("[INFO] No Issue ID provided. Skipping status update.")
        return
        
    print(f"[INFO] Updating Wiz Issue {issue_id} status to {status}...")
    try:
        client_id, client_secret = _get_wiz_api_credentials()
        token, dc = _request_wiz_api_token(client_id, client_secret)
        
        mutation = """
        mutation UpdateIssue($issueId: ID!, $patch: UpdateIssuePatch) {
          updateIssue(input: {id: $issueId, patch: $patch}) {
            issue {
              id
              status
            }
          }
        }
        """
        
        variables = {
            "issueId": issue_id,
            "patch": {
                "status": status
            }
        }
        
        response = _query_wiz_api(mutation, variables, dc, token)
        if "errors" in response:
            print(f"[WARN] GraphQL errors returned when updating status: {json.dumps(response['errors'])}")
        else:
            new_status = response.get("data", {}).get("updateIssue", {}).get("issue", {}).get("status")
            print(f"[INFO] Successfully updated Wiz Issue status to: {new_status}")
    except Exception as e:
        print(f"[WARN] Failed to update Wiz Issue status: {e}")


def _quarantine_file_path(source_bucket, key, finding_md5, quarantine_bucket):
    """Client-side copy of S3 object to quarantine bucket and delete from source."""
    print(f"[INFO] Processing quarantine for s3://{source_bucket}/{key}")
    
    try:
        version_id = _find_malicious_version(source_bucket, key, finding_md5)
    except FileNotFoundError:
        print(f"[WARN] File s3://{source_bucket}/{key} no longer exists. Skipping.")
        return None

    dest_key = f"{source_bucket}/{key}_{version_id}"

    # Get Object (Download)
    try:
        response = s3.get_object(Bucket=source_bucket, Key=key, VersionId=version_id)
        content = response["Body"].read()
    except ClientError as e:
        print(f"[ERROR] Failed to download {key}: {e.response['Error']['Message']}")
        raise e

    # Put Object (Upload)
    try:
        s3.put_object(
            Bucket=quarantine_bucket,
            Key=dest_key,
            Body=content,
            Metadata={
                ORIGINAL_VERSION_HEADER: version_id,
                ORIGINAL_SOURCE_ARN_HEADER: f"arn:aws:s3:::{source_bucket}/{key}",
                QUARANTINED_AT_HEADER: datetime.now(timezone.utc).isoformat()
            }
        )
        print(f"[INFO] Uploaded to s3://{quarantine_bucket}/{dest_key}")
    except ClientError as e:
        print(f"[ERROR] Failed to upload {dest_key}: {e.response['Error']['Message']}")
        raise e

    # Delete Object from Source
    try:
        s3.delete_object(Bucket=source_bucket, Key=key, VersionId=version_id)
        print(f"[INFO] Deleted original s3://{source_bucket}/{key} (Version: {version_id})")
    except ClientError as e:
        print(f"[ERROR] Failed to delete original: {e.response['Error']['Message']}. Cleaning up quarantine copy.")
        try:
            s3.delete_object(Bucket=quarantine_bucket, Key=dest_key)
        except:
            pass
        raise e

    return dest_key


def _restore_file_path(source_bucket, key, quarantine_bucket):
    """Restores a quarantined object back to its source bucket, cleaning up the quarantine copy."""
    print(f"[INFO] Restoring quarantined file for s3://{source_bucket}/{key}")
    
    prefix = f"{source_bucket}/{key}_"
    try:
        response = s3.list_objects_v2(Bucket=quarantine_bucket, Prefix=prefix)
    except ClientError as e:
        print(f"[ERROR] Failed to list quarantine bucket: {e}")
        raise e

    contents = response.get("Contents", [])
    if not contents:
        print(f"[WARN] No quarantined files found for s3://{source_bucket}/{key} in {quarantine_bucket}")
        return []

    restored_files = []
    for obj in contents:
        quarantined_key = obj["Key"]
        print(f"[INFO] Found quarantined file: {quarantined_key}")
        
        # 1. Download from Quarantine
        try:
            resp = s3.get_object(Bucket=quarantine_bucket, Key=quarantined_key)
            content = resp["Body"].read()
            metadata = resp.get("Metadata", {})
            original_version_id = metadata.get("original-version-id")
        except ClientError as e:
            print(f"[ERROR] Failed to read quarantined file {quarantined_key}: {e.response['Error']['Message']}")
            raise e

        # 2. Upload back to Source Bucket (creating a new version)
        print(f"[INFO] Restoring file content back to s3://{source_bucket}/{key}...")
        try:
            s3.put_object(
                Bucket=source_bucket,
                Key=key,
                Body=content
            )
        except ClientError as e:
            print(f"[ERROR] Failed to restore object to source {key}: {e.response['Error']['Message']}")
            raise e

        # 3. Clean up Quarantine
        print(f"[INFO] Deleting quarantined copy {quarantined_key}...")
        try:
            s3.delete_object(Bucket=quarantine_bucket, Key=quarantined_key)
        except ClientError as e:
            print(f"[WARN] Failed to delete quarantined copy: {e.response['Error']['Message']}")
            
        restored_files.append({
            "key": key,
            "original_version": original_version_id
        })
        
    return restored_files


def _restore_bucket_malware(source_bucket, quarantine_bucket):
    """Restores all quarantined objects belonging to a specific source bucket."""
    print(f"[INFO] Restoring all quarantined files for bucket {source_bucket}")
    
    prefix = f"{source_bucket}/"
    try:
        response = s3.list_objects_v2(Bucket=quarantine_bucket, Prefix=prefix)
    except ClientError as e:
        print(f"[ERROR] Failed to list quarantine bucket: {e}")
        raise e

    contents = response.get("Contents", [])
    if not contents:
        print(f"[INFO] No quarantined files found for bucket {source_bucket} in {quarantine_bucket}")
        return []

    restored_files = []
    for obj in contents:
        quarantined_key = obj["Key"]
        try:
            # 1. Fetch object metadata to resolve original source ARN
            resp = s3.get_object(Bucket=quarantine_bucket, Key=quarantined_key)
            content = resp["Body"].read()
            metadata = resp.get("Metadata", {})
            
            original_arn = metadata.get("original-source-arn")
            original_version_id = metadata.get("original-version-id")
            
            if not original_arn:
                print(f"[WARN] Quarantined object {quarantined_key} is missing original-source-arn header. Skipping.")
                continue
                
            # Parse key from original ARN
            _, key, _ = _parse_s3_resource(original_arn)
            if not key:
                continue

            # 2. Upload back to Source Bucket
            print(f"[INFO] Restoring file content back to s3://{source_bucket}/{key}...")
            s3.put_object(
                Bucket=source_bucket,
                Key=key,
                Body=content
            )

            # 3. Clean up Quarantine
            s3.delete_object(Bucket=quarantine_bucket, Key=quarantined_key)
            
            restored_files.append({
                "key": key,
                "original_version": original_version_id
            })
            print(f"[INFO] Restored s3://{source_bucket}/{key} successfully.")
        except Exception as e:
            print(f"[ERROR] Failed to restore quarantined file {quarantined_key}: {e}")

    return restored_files


def lambda_handler(event, context):
    """Main Lambda Entrypoint for SNS Events."""
    # 1. Parse SNS Event Wrapper
    try:
        sns_record = event['Records'][0]['Sns']
        sns_message = sns_record['Message']
        payload = json.loads(sns_message)
        print(f"[INFO] Received payload: {json.dumps(payload)}")
    except Exception as e:
        print(f"[ERROR] Failed to parse SNS event payload: {e}")
        raise e

    # 2. Extract configuration
    directive = payload.get("directive", "quarantine").lower()
    issue_id = payload.get("issueId")
    resource_id = payload.get("resourceId") or payload.get("providerUniqueId")
    
    if not resource_id:
        resource_id = payload.get("resource", {}).get("providerUniqueId") or payload.get("resource", {}).get("id")
        
    if not resource_id:
         raise ValueError(f"Could not locate S3 ARN or providerUniqueId in payload")

    # 3. Resolve Quarantine Bucket
    try:
        account_id = sts.get_caller_identity()["Account"]
        quarantine_bucket = _get_quarantine_bucket(account_id)
    except Exception as e:
        print(f"[ERROR] Failed to resolve quarantine bucket: {e}")
        raise e

    # Parse source bucket and key
    source_bucket, key, finding_md5 = _parse_s3_resource(resource_id)

    # =========================================================================
    # DIRECTIVE: QUARANTINE
    # =========================================================================
    if directive == "quarantine":
        # Start by moving status to IN_PROGRESS
        _update_issue_status(issue_id, "IN_PROGRESS")

        comment = f"🔒 **Wiz S3 Malware Quarantine Action**\n\n"
        comment += f"*   **Source Bucket:** `{source_bucket}`\n"
        comment += f"*   **Region:** `{REGION}`\n\n"
        
        # Case A: Specific object
        if key:
            print(f"[INFO] Triggering quarantine on single file path: {key}")
            if not finding_md5:
                finding_md5 = _extract_md5_from_finding(payload)
                
            try:
                dest_key = _quarantine_file_path(source_bucket, key, finding_md5, quarantine_bucket)
                if dest_key:
                    comment += f"✅ **Quarantined file:** `{key}`\n"
                    comment += f"*   **Quarantine Path:** `s3://{quarantine_bucket}/{dest_key}`\n"
                else:
                    comment += f"⚠️ **File already removed or missing:** `{key}` (skipped)\n"
            except Exception as e:
                comment += f"❌ **Failed to quarantine file:** `{key}`\n"
                comment += f"*   **Error:** `{str(e)}`\n"
                _add_issue_comment(issue_id, comment)
                raise e

        # Case B: Bucket-level target -> Query Graph
        else:
            bucket_uuid = payload.get("id") or payload.get("resource", {}).get("id")
            projects = payload.get('projects', [])
            project_id = projects[0].get('id') if projects else "*"
            
            print(f"[INFO] Triggering query-based quarantine for bucket UUID: {bucket_uuid}")
            try:
                malware_files = _get_malware_files_for_bucket(bucket_uuid, project_id)
            except Exception as e:
                comment += f"❌ **Failed to query Wiz API for malware list**\n*   **Error:** `{str(e)}`\n"
                _add_issue_comment(issue_id, comment)
                raise e

            if not malware_files:
                comment += "ℹ️ No active S3 malware findings found in Wiz API for this bucket. Action skipped.\n"
                _add_issue_comment(issue_id, comment)
                return {"statusCode": 200, "body": "No malware found."}

            comment += f"Found **{len(malware_files)}** infected file(s). Processing:\n\n"
            
            failed_quarantines = []
            quarantined_files = []
            for file_info in malware_files:
                file_key = file_info["key"]
                file_md5 = file_info["md5"]
                try:
                    dest_key = _quarantine_file_path(source_bucket, file_key, file_md5, quarantine_bucket)
                    if dest_key:
                        quarantined_files.append(file_key)
                    else:
                        comment += f"*   ⚠️ `{file_key}` already missing (skipped)\n"
                except Exception as e:
                    failed_quarantines.append({"key": file_key, "error": str(e)})

            if quarantined_files:
                comment += f"✅ **Successfully Quarantined:**\n"
                for f in quarantined_files:
                    comment += f"*   `{f}`\n"
                    
            if failed_quarantines:
                comment += f"\n❌ **Failed to Quarantine:**\n"
                for f in failed_quarantines:
                    comment += f"*   `{f['key']}` (Error: `{f['error']}`)\n"
                _add_issue_comment(issue_id, comment)
                raise Exception(f"Quarantine completed with failures: {json.dumps(failed_quarantines)}")

        _add_issue_comment(issue_id, comment)

    # =========================================================================
    # DIRECTIVE: UNQUARANTINE (RESTORE)
    # =========================================================================
    elif directive == "unquarantine":
        # Moving status to IN_PROGRESS when restoring as well
        _update_issue_status(issue_id, "IN_PROGRESS")

        comment = f"🔓 **Wiz S3 Malware Restore (Unquarantine) Action**\n\n"
        comment += f"*   **Source Bucket:** `{source_bucket}`\n\n"

        # Case A: Specific object
        if key:
            print(f"[INFO] Restoring single file path: {key}")
            try:
                restored = _restore_file_path(source_bucket, key, quarantine_bucket)
                if restored:
                    comment += f"✅ **Restored file:** `{key}`\n"
                    comment += f"*   Original quarantined copy has been deleted.\n"
                else:
                    comment += f"⚠️ **Could not find quarantined copy for:** `{key}` in quarantine bucket.\n"
            except Exception as e:
                comment += f"❌ **Failed to restore file:** `{key}`\n"
                comment += f"*   **Error:** `{str(e)}`\n"
                _add_issue_comment(issue_id, comment)
                raise e

        # Case B: Bucket-level target -> Restore all files belonging to this bucket
        else:
            print(f"[INFO] Restoring all quarantined files for bucket: {source_bucket}")
            try:
                restored_list = _restore_bucket_malware(source_bucket, quarantine_bucket)
                if restored_list:
                    comment += f"✅ **Successfully Restored {len(restored_list)} file(s):**\n"
                    for r in restored_list:
                        comment += f"*   `{r['key']}`\n"
                else:
                    comment += f"ℹ️ No quarantined copies found under prefix `{source_bucket}/`.\n"
            except Exception as e:
                comment += f"❌ **Failed to execute bucket-level restore**\n*   **Error:** `{str(e)}`\n"
                _add_issue_comment(issue_id, comment)
                raise e

        _add_issue_comment(issue_id, comment)

    else:
        raise ValueError(f"Unknown execution directive: {directive}")

    return {
        "statusCode": 200,
        "body": json.dumps("Action completed successfully.")
    }
