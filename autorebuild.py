import subprocess
import sys
import time
import os


def call(args):
    print("Calling", args, file=sys.stderr)
    subprocess.check_call(args)


def main():
    call(["python3", "gensrrules.py"])
    try:
        call(["git", "diff-index", "--quiet", "HEAD"])
    except subprocess.CalledProcessError:
        call(["git", "add", "fullrules.conf", "fullrules.txt"])
        call(["git", "commit", "-m", "Rebuild full rules"])
        call(["git", "push"])
        print("Rules generated and pushed successfully", file=sys.stderr)
    else:
        print("Generated output is unchanged. Skipping this push.", file=sys.stderr)
    finally:
        time.sleep(3600)
        call(["git", "pull", "--rebase"])
        # This script contents may be changed after the pull, so instead of looping, we call `exec`.
        os.execlp("python3", "python3", __file__)


if __name__ == "__main__":
    main()
