"""Run a single image though all caches
"""

import argparse
import os
import subprocess as sp
import sys
from pathlib import Path
from typing import Optional

DEFAULT_IMAGES = (
    "/System/Library/PrivateFrameworks/PreferencesUI.framework/PreferencesUI",
    "/System/Library/PrivateFrameworks/RunningBoard.framework/RunningBoard",
    "/System/iOSSupport/System/Library/PrivateFrameworks/WeatherUI.framework/Versions/A/WeatherUI",  # noqa
    "/System/Library/PrivateFrameworks/DigitalAccess.framework/DigitalAccess",
    "/System/Library/PrivateFrameworks/AccountSettings.framework/AccountSettings"  # noqa
)


class Arguments:
    executable_path: Optional[Path]
    caches_path: Optional[Path]
    output_dir: Optional[Path]
    images: tuple[str, ...]
    pass


def findCaches(cachesPath: Path) -> tuple[Path, ...]:
    caches: list[Path] = []
    for arch in cachesPath.iterdir():
        for cache in arch.iterdir():
            caches.append(cache)
            pass
        pass

    return tuple(caches)


def runCache(
    executablePath: Path,
    cachePath: Path,
    cacheName: str,
    outputDir: Path,
    images: tuple[str, ...]
) -> None:
    for image in images:
        args = [
            executablePath,
            "-V",
            "-e",
            image,
            "-o",
            outputDir / f"{cacheName}_{image.split('/')[-1]}",
            cachePath
        ]
        proc = sp.run(args, stdout=sp.PIPE, stderr=sp.STDOUT)
        if f"Unable to find image '{image}'" in str(proc.stdout):
            continue
        else:
            print(f"------: {cacheName} :------")
            sys.stdout.buffer.write(proc.stdout)
            sys.stdout.flush()
            print("------------\n")
            return

    print(f"Unable to find suitable image for {cacheName}.\n", file=sys.stderr)
    pass


def main() -> None:
    argParser = argparse.ArgumentParser("RunAllCaches_SingleImage")
    argParser.add_argument("--executable-path", type=Path,
                           default=os.environ.get("TESTING_DYLDEX_PATH"),
                           help="Path to dyldex, can be set with the "
                           "environmental variable 'TESTING_DYLDEX_PATH'.")
    argParser.add_argument("--caches-path", type=Path,
                           default=os.environ.get("TESTING_CACHES_PATH"),
                           help="The folder containing the caches to test, "
                           "can be set with the environmental variable "
                           "'TESTING_CACHES_PATH'.")
    argParser.add_argument("--output-dir", type=Path,
                           default=os.environ.get("TESTING_OUTPUT_DIR"),
                           help="The output directory, can be set with "
                           "TESTING_OUTPUT_DIR")
    argParser.add_argument("--images", type=tuple, default=DEFAULT_IMAGES,
                           help="Images to test with a cache, tried in order "
                           "if a cache does not contain a image.")

    args = argParser.parse_args(namespace=Arguments())
    if not args.executable_path:
        print("--executable-path or TESTING_DYLDEX_PATH needs to be "
              "set.\n", file=sys.stderr)
        argParser.print_help()
        argParser.exit()
    if not args.caches_path:
        print("--caches-path or TESTING_CACHES_PATH needs to be set.\n",
              file=sys.stderr)
        argParser.print_help()
        argParser.exit()
    if not args.output_dir:
        print("--output-dir or TESTING_OUTPUT_DIR needs to be set.\n",
              file=sys.stderr)
        argParser.print_help()
        argParser.exit()

    for cache in findCaches(args.caches_path):
        cacheName = f"{cache.parent.name}_{cache.name}"
        runCache(args.executable_path, cache, cacheName, args.output_dir,
                 args.images)
        pass
    pass


if __name__ == "__main__":
    main()
    pass
