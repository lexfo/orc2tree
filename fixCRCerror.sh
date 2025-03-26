#!/bin/bash

BIN7Z="7z"

# Check if 7-Zip is installed
if ! type "$BIN7Z" > /dev/null; then
    printf "error: you have to install 7z!\n" 1>&2
    exit 1
fi

# Check if the corrupted archive is provided
if [ -z "$1" ]; then
    printf "usage: %s CORRUPTED_DFIR_ORC\n" "$0" 1>&2
    exit 1
fi

# Check if the given argument is a file
if [ ! -f "$1" ]; then
    printf "%s: %s: No such file or directory\n" "$0" "$1" 1>&2
    exit 1
fi

# Get paths of the given file and its parent directory
file_path=$(realpath "$1")
file_name=$(basename "$file_path")
root_path=$(dirname "$file_path")

# Build paths for output
tmp_dir=${root_path}/${file_name/.7z/.tmp}
fixed_file_path=${root_path}/${file_name/.7z/.fixed.7z}
fixed_file_name=$(basename "$fixed_file_path")
corrupted_file_path=${root_path}/${file_name/.7z/.corrupted.7z}
corrupted_file_name=$(basename "$corrupted_file_path")

# Extracting the corrupted archive into the temporary folder
mv "${file_path}" "${corrupted_file_path}"
printf "[*] Corrupted file: %s (%s)\n" "${corrupted_file_name}" \
    "$(du -sh "${corrupted_file_path}" | cut -f1)"

printf "[*] Extracting '%s' using '%s'\n" "${corrupted_file_name}" "${BIN7Z}"
${BIN7Z} x "${corrupted_file_path}" -O"${tmp_dir}" > /dev/null

# Recreating a fresh archive
printf "[*] Recreating '%s' using '%s'\n" "${fixed_file_name}" "${BIN7Z}"
cd "${tmp_dir}" && ${BIN7Z} a "${fixed_file_path}" * >/dev/null

printf "[*] Fixed file: %s (%s)\n" "${fixed_file_name}" \
    "$(du -sh "${fixed_file_path}" | cut -f1)"
mv "${fixed_file_path}" "${file_path}"

printf "[*] Cleaning extracted files (%s)\n" "$(basename "${tmp_dir}")"
rm -r "${tmp_dir}"
