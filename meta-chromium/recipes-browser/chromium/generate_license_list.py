#!/usr/bin/env python3
"""
This script can be used to generate LIC_FILES_CHKSUM in chromium.inc.

It uses Chromium's own tools/licenses/licenses.py script to scan for third_party
directories and license files. This means its output is generated on a
best-effort basis, as some directories are non-compliant upstream or may not be
found. It might also include directories which are not used in a
Yocto/OpenEmbedded build.
"""

import argparse
import hashlib
import os
import sys

# Common license file names to search for
COMMON_LICENSE_NAMES = [
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "COPYING",
    "COPYING.txt",
    "COPYING.md",
    "NOTICE",
    "NOTICE.txt",
    "NOTICE.md",
    "COPYRIGHT",
    "COPYRIGHT.txt",
    "COPYRIGHT.md",
]

# These are directories that are known to cause licenses.LicenseError to be
# thrown because but should not cause a failure in this script for
# different reasons.
SKIPPED_DIRECTORIES = (
    # These directories are not part of the Chromium tarballs (upstream's
    # export_tarball.py declares them "non-essential" or plain test
    # directories, and their README.chromium in the git repositories mark
    # them as NOT_SHIPPED).
    "chrome/test/data",
    "third_party/hunspell_dictionaries",
    # android_protobuf is checked out and used only in Android builds, so a
    # LicenseError will be thrown because README.chromium will point to a
    # file that is not present in a Chromium tarball.
    "third_party/android_protobuf",
    # Starting with M61, Chromium is shipping its own pinned version of
    # depot_tools. It's only part of the build and the directory structure
    # does not follow the standard. Skip it.
    "third_party/depot_tools",
    # M63 and later: we do not consume win_build_output.
    "third_party/win_build_output",
    # M67: third_party/fuchsia-sdk has no LICENSE file. This is not used in
    # Linux builds though.
    # https://bugs.chromium.org/p/chromium/issues/detail?id=847821
    "third_party/fuchsia-sdk",
)


def find_chromium_licenses(chromium_root):
    """Look for license files in a Chromium checkout and return a set with all
    files that are actually shipped and used in the final Chromium binary."""
    try:
        import licenses
    except ImportError:
        raise ImportError(
            "Failed to import licenses.py. Make sure %s "
            "contains tools/licenses/licenses.py." % chromium_root
        )

    # Make sure the main Chromium LICENSE file is always present.
    license_files = set([os.path.join(chromium_root, "LICENSE")])

    for d in licenses.FindThirdPartyDirs(chromium_root):
        if d in SKIPPED_DIRECTORIES:
            continue

        errors = []
        try:
            metadata_list, errors = licenses.ParseDir(d, chromium_root)
        except licenses.LicenseError as e:
            errors.append(str(e))

        if len(errors) != 0:
            # In M122, changes to the upstream script have resulted in a huge
            # mass of errors. Going through all of them isn't feasible, so we
            # just print them for now.
            e = "'" + "', '".join(error.strip() for error in errors) + "'"
            print("Exception(s) in directory %s: %s" % (d, e))

            # Even if metadata parsing failed, try to find common license files
            # in the directory to avoid missing important licenses
            _try_find_common_license_files(d, chromium_root, license_files)
            continue

            # if input('Ignore (y)? ') == 'y':
            #     continue
            # raise Exception(e)

        for metadata in metadata_list:
            # We are not interested in licenses for projects that are not marked as
            # used in the final product (ie. they might be optional development
            # aids, or only used in a build).
            if metadata["Shipped"] == licenses.YES:
                license_files.update(set(metadata["License File"]))
    return license_files


def print_license_list(chromium_root, output_file, comprehensive=False):
    """Print a list of Chromium license paths and checksums in a format
    suitable for use in a Yocto recipe."""
    licenses = {}

    if comprehensive:
        print("Using comprehensive recursive search for license files...")
        license_files = find_all_license_files_recursive(chromium_root)
    else:
        print("Using metadata-based search for license files...")
        license_files = find_chromium_licenses(chromium_root)

    for license_file in license_files:
        with open(license_file, "rb") as file_handle:
            license_hash = hashlib.md5(file_handle.read()).hexdigest()
        license_relpath = os.path.relpath(license_file, chromium_root)
        licenses[license_relpath] = license_hash

    print(f"Found {len(licenses)} license files total.")

    with open(output_file, "w") as out:
        out.write('LIC_FILES_CHKSUM = "\\\n')
        for f in sorted(licenses):
            out.write("    file://${S}/%s;md5=%s \\\n" % (f, licenses[f]))
        out.write('    "\n')


def _try_find_common_license_files(directory, chromium_root, license_files_set):
    """Try to find common license file names in a directory when metadata parsing fails."""
    dir_path = os.path.join(chromium_root, directory)
    if not os.path.exists(dir_path):
        return

    # Build list of directories to search (current + 1 level + 2 levels deep)
    dirs_to_search = [dir_path]

    try:
        # Add first level subdirectories
        first_level_dirs = [
            os.path.join(dir_path, d)
            for d in os.listdir(dir_path)
            if os.path.isdir(os.path.join(dir_path, d))
        ]
        dirs_to_search.extend(first_level_dirs)

        # Add second level subdirectories for deeply nested structures
        # This helps with directories like android_deps/autorolled/committed/libs/*/
        try:
            second_level_dirs = [
                os.path.join(subdir, d)
                for subdir in first_level_dirs
                for d in os.listdir(subdir)
                if os.path.isdir(os.path.join(subdir, d))
            ]
            dirs_to_search.extend(second_level_dirs)
        except (OSError, PermissionError):
            pass
    except (OSError, PermissionError):
        pass

    # Search for license files in all discovered directories
    for license_name in COMMON_LICENSE_NAMES:
        for search_dir in dirs_to_search:
            license_path = os.path.join(search_dir, license_name)
            if os.path.isfile(license_path):
                rel_path = os.path.relpath(license_path, chromium_root)
                print("  Found fallback license file: %s" % rel_path)
                license_files_set.add(license_path)


def find_all_license_files_recursive(chromium_root):
    """Find all license files by recursively searching the entire tree.
    This is a more comprehensive but slower approach."""
    license_files = set()

    # Start with the main LICENSE file
    main_license = os.path.join(chromium_root, "LICENSE")
    if os.path.isfile(main_license):
        license_files.add(main_license)

    # Walk through the entire chromium tree looking for license files
    for root, dirs, files in os.walk(chromium_root):
        # Skip some obviously non-relevant directories for performance
        # Also skip directories from SKIPPED_DIRECTORIES to avoid unnecessary traversal
        rel_root = os.path.relpath(root, chromium_root)
        if rel_root in SKIPPED_DIRECTORIES or any(rel_root.startswith(skip_dir) for skip_dir in SKIPPED_DIRECTORIES):
            dirs[:] = []  # Don't descend into skipped directories
            continue
            
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d not in ["__pycache__", "node_modules"]
        ]

        for filename in files:
            if filename in COMMON_LICENSE_NAMES:
                license_path = os.path.join(root, filename)
                license_files.add(license_path)
                rel_path = os.path.relpath(license_path, chromium_root)
                print("Found license file: %s" % rel_path)

    return license_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "chromium_root",
        help="Path to the root directory of a Chromium "
        "checkout or extracted tarball.",
    )
    parser.add_argument(
        "output_file", help="File to write the output to (it will be " "overwritten)"
    )
    parser.add_argument(
        "--comprehensive",
        action="store_true",
        help="Use comprehensive recursive search for all license files "
        "(slower but finds more files)",
    )
    args = parser.parse_args()

    tools_licenses_dir = os.path.join(args.chromium_root, "tools/licenses")
    if not os.path.isdir(tools_licenses_dir):
        print("%s does not look like a valid directory." % tools_licenses_dir)
        sys.exit(1)
    sys.path = [tools_licenses_dir] + sys.path

    print_license_list(args.chromium_root, args.output_file, args.comprehensive)
