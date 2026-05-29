import os
from git import Repo
from webdav4.client import Client
from pathlib import PurePath

WEBDAV_URI = os.environ.get("WEBDAV_URI", "")
WEBDAV_USERNAME = "dav"
WEBDAV_PASSWORD = os.environ.get("WEBDAV_PASS", "")

if not WEBDAV_PASSWORD:
    print("Error: WEBDAV_PASS environment variable not set.")
    raise SystemExit(1)


def upload_modified_srs_files():
    repo = Repo(".")
    modified_files = [item.a_path for item in repo.index.diff(None)]

    srs_files_to_upload = [
        PurePath(f) for f in modified_files if f and f.endswith(".srs")
    ]

    if not srs_files_to_upload:
        print("No modified .srs files found to upload.")
        return

    client = Client(base_url=WEBDAV_URI, auth=(WEBDAV_USERNAME, WEBDAV_PASSWORD))

    print(f"Attempting to upload {len(srs_files_to_upload)} .srs files...")
    for file_path in srs_files_to_upload:
        remote_path = file_path.relative_to(".")
        client.upload_file(
            from_path=file_path, to_path="/" + str(remote_path), overwrite=True
        )
        print(f"Successfully uploaded: {file_path}")


if __name__ == "__main__":
    upload_modified_srs_files()
