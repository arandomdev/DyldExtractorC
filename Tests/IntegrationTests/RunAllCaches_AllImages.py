import argparse
import os
import pathlib
import subprocess
import sys
import multiprocessing
from typing import Generator, Optional

RETRY_MESSAGE = "The paging file is too small"
RETRY_CORE_COUNT = str(multiprocessing.cpu_count() // 2)
BASE_PARAMS = (
    "--disable-output",
    "-v",
    "-q")


class Arguments:
    executable_path: pathlib.Path
    caches_path: pathlib.Path
    cache_filters: Optional[list[str]]
    pause: bool
    pass


def getArguments() -> Arguments:
    parser = argparse.ArgumentParser("RunAllCaches_AllImages")
    parser.add_argument("--executable-path", type=pathlib.Path,
                        default=os.environ.get(
                            "TESTING_DYLDEX_ALL_MULTIPROCESS_PATH"),
                        help="Path to dyldex, can be set with the "
                        "environmental variable "
                        "'TESTING_DYLDEX_ALL_MULTIPROCESS_PATH'.")
    parser.add_argument("--caches-path", type=pathlib.Path,
                        default=os.environ.get("TESTING_CACHES_PATH"),
                        help="The folder containing the caches to test, "
                        "can be set with the environmental variable "
                        "'TESTING_CACHES_PATH'.")
    parser.add_argument("--cache-filters", nargs="+", type=str,
                        help="A list of keywords to filter out caches that "
                        "should not be processed.")
    parser.add_argument("--pause", action=argparse.BooleanOptionalAction,
                        default=False,
                        help="Pause before running the next cache.")

    args = parser.parse_args(namespace=Arguments())
    if not args.executable_path:
        print("--executable-path or TESTING_DYLDEX_ALL_MULTIPROCESS_PATH needs"
              " to be set.\n", file=sys.stderr)
        parser.print_help()
        parser.exit()
    if not args.caches_path:
        print("--caches-path or TESTING_CACHES_PATH needs to be set.\n",
              file=sys.stderr)
        parser.print_help()
        parser.exit()
    return args


def getCachePaths(
    cachePath: pathlib.Path,
    filters: Optional[list[str]]
) -> Generator[pathlib.Path, None, None]:
    for arch in cachePath.iterdir():
        for cache in arch.iterdir():
            if cache.is_dir():
                path = next(c for c in cache.iterdir() if c.suffix == "")
            else:
                path = cache

            if filters and next((f for f in filters if f in str(path)), None):
                continue
            yield path


def runCache(exe: pathlib.Path, cachePath: pathlib.Path) -> bool:
    print(f"\nRunning {cachePath}")
    params = (exe, cachePath) + BASE_PARAMS

    proc = subprocess.Popen(params, stderr=subprocess.PIPE, encoding="utf-8")
    assert proc.stderr is not None

    errorMessages = ""
    while True:
        errorFrag = proc.stderr.read()
        if errorFrag == "" and proc.poll() is not None:
            break
        if errorFrag:
            errorMessages += errorFrag
            sys.stdout.write(errorFrag)
            sys.stdout.flush()

    if proc.returncode != 0 and RETRY_MESSAGE in errorMessages:
        print("Re-processing with lower thread count")
        proc2 = subprocess.run(params + ("-j", RETRY_CORE_COUNT))
        if proc2.returncode != 0:
            return False
    elif proc.returncode != 0 and RETRY_MESSAGE not in errorMessages:
        return False

    return True


def main():
    args = getArguments()

    for cachePath in getCachePaths(args.caches_path, args.cache_filters):
        if args.pause:
            input(f"Press enter to process {cachePath}")

        if not runCache(args.executable_path, cachePath):
            return
        pass
    pass


if __name__ == "__main__":
    main()
