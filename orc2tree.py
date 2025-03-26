#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import coloredlogs
import logging
import hashlib
import pandas
import py7zr
import re
import shutil
import json
import glob
import zipfile

from pathlib import Path
from io import BytesIO

# -----------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

TOOLNAME = Path(__file__).stem

# =============================================================================
# -----------------------------------------------------------------------------
# =============================================================================

def get_args():
    """
    Parse command-line arguments and return the parsed arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description='extracts DFIR archives ' \
        'harvested by the DFIR-ORC tool (https://dfir-orc.github.io) and ' \
        'reorganizes them according to their original location on the disk. ' \
        'The script uses the metadata from "GetThis.csv" populated by the ' \
        'DFIR-ORC tool to reconstruct the tree of the original disk(s).')

    parser.add_argument(
        '--zip',
        nargs='+',
        metavar='ZIPFILE',
        dest='zippaths',
        default=[],
        help='one or more archives from DFIR-ORC (7-Zip or ZIP)'
    )

    parser.add_argument(
        '--json',
        nargs='+',
        metavar='JSONFILE',
        dest='jsonfiles',
        default=[],
        help='the DFIR-ORC Execution Outline'
    )

    parser.add_argument(
        '--outdir',
        metavar='DIRNAME',
        default=Path.cwd(),
        help='the directory in which to extract files (default: ".")'
    )

    parser.add_argument(
        '--check',
        action='store_true',
        help='check for SHA1 of extracted files'
    )

    parser.add_argument(
        '--key',
        metavar='KEYFILE',
        default=None,
        help='the private key for encrypted archives'
    )

    parser.add_argument(
        '--fix-crc',
        action='store_true',
        help='use an external script to resolve CRC errors'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='enable debug output'
    )

    args = parser.parse_args()

    args.zippaths = expand_wildcards(args.zippaths)
    args.jsonfiles = expand_wildcards(args.jsonfiles)

    return args

# -----------------------------------------------------------------------------

def expand_wildcards(wildcards: list):
    """
    If any wildcard pattern is used, expand it to get the actual filenames.

    Args:
        wildcards (list): A list of non-parsed paths with wildcards

    Returns:
        list: The list of unique paths
    """
    return list(set(Path(f) for wc in wildcards for f in glob.glob(wc)))

# -----------------------------------------------------------------------------

def define_console_logging(debug: bool = False):
    """
    Set up logging to the console with an optional debug level.

    Args:
        debug (bool): Enable debug mode if True (default: False).
    """
    if __name__ == '__main__':
        logger = logging.getLogger()

    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Enable verbose formatting in debug mode
    dbgfmt = '%(levelname)8s [%(asctime)s][%(name)20s] %(message)s'

    # Setup console logging
    coloredlogs.install(
        level=logging.DEBUG if debug else logging.INFO,
        logger=logger, 
        fmt= '%(message)s' if not debug else dbgfmt,
        datefmt='%Y-%m-%dT%H:%M:%S%z'
    )

# -----------------------------------------------------------------------------

def define_file_logging(logfile: Path, debug: bool = False):
    """
    Set up logging to a file with an optional debug level.

    Args:
        logfile (Path): Path to the log file.
        debug (bool): Enable debug mode if True (default: False).
    """
    if __name__ == '__main__':
        logger = logging.getLogger()

    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Setup file logging
    file_handler = logging.FileHandler(logfile, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        fmt='[%(asctime)s] %(levelname)8s - %(name)20s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z'
    ))
    logger.addHandler(file_handler)

    logger.debug(f'Log file initialized: {logfile.relative_to(Path.cwd())}')

# -----------------------------------------------------------------------------

def list_zippaths(zippaths: list, jsonfiles: list):
    """
    Build the list of archives to be extracted using the given filenames 
    and/or the data in the given JSON files.

    Args:
        zippaths (list): List of archive filenames.
        jsonfiles (list): List of JSON files (DFIR-ORC Execution Outline).

    Returns:
        list: The archives list.
    """

    # For each given JSON file, search for DFIR-ORC archives
    for jsonfile in jsonfiles:
        zippaths += get_zippaths_from_json(jsonfile)

    # Ensure the absolute path is stored in the list
    zippaths = list(set(fn.absolute() for fn in zippaths))
    if len(zippaths) == 0 and len(jsonfiles) == 0:
        logger.info("No archives provided, please use '--json' or '--zip'.")
    else:
        logger.info('JSON and 7-Zip files specified as arguments identified ' \
            f'{len(zippaths)} unique 7-Zip archives, ready to extract')

    return zippaths

# -----------------------------------------------------------------------------

def get_zippaths_from_json(jsonfile: Path):
    """
    Retrieve the name of the harvested archives from a JSON file.

    Args:
        jsonfile (Path): Path of JSON file.

    Returns:
        list: The archives list.
    """
    try:
        logger.info(f'{jsonfile.name}: ' \
            'Search for information in the JSON file ')

        # Read the DFIR-ORC filenames from the given JSON file
        with open(jsonfile, 'r') as file:
            data = json.load(file)

        # Retrieve the DFIR-ORC version and outline
        try:
            outline = data.get('dfir-orc').get('outline')
            version = outline.get('version')
        except AttributeError as e: # DFIR-ORC older than v10.1.0
            outline = data.get('dfir-orc')
            version = outline.get('dfir_orc_id')
        finally:
            zipnames = [a['file'] for a in outline.get('archives')]
            logger.debug(f'{jsonfile.name}: {len(zipnames)} ' \
                f'archives retrieved for DFIR-ORC {version}')

        # Return the list, assuming the archives are alongside the JSON file
        return [jsonfile.with_name(zipname) for zipname in zipnames]
    
    except FileNotFoundError as err:
        logger.debug(f'Listing archives: FileNotFoundError: {err}')
        logger.warning(f'{jsonfile.name}: File not found')
    
    except TypeError as err:
        logger.debug(f'Listing archives: TypeError: {err}')
        logger.warning(f'{jsonfile.name}: No archives found')
    
    except ValueError as err:
        logger.debug(f'Listing archives: ValueError: {err}')
        logger.warning(f'{jsonfile.name}: Invalid DFIR-ORC Execution Outline')

    return []

# -----------------------------------------------------------------------------

def extract_zipfile(zippath: Path, outdir: Path, key: Path, fix_crc: bool = False):
    """
    Extract a main DFIR-ORC archive.

    Args:
        zippath (Path): Path to the archive.
        outdir (Path): The directory in which to extract files.
        key (Path): The key for decryption, if necessary (default: None).
        fix_crc (bool) : Try to fix the CRC error if True (default: False).

    Returns:
        list: The directory where the child archives have been extracted.
    """
    md5filename = hashlib.md5(zippath.name.encode()).hexdigest()
    dstpath = outdir.joinpath(f'{TOOLNAME}.{md5filename}.tmp').absolute()
    logger.debug(f'Output directory: {dstpath.relative_to(Path.cwd())}')

    try:

        if zippath.suffix.lower() == '.zip':
            # Extract all files from the main archive
            with zipfile.ZipFile(zippath, 'r') as z:
                logger.info(f'{zippath.name}: Retrieving child archives...')
                z.extractall(dstpath)
            logger.debug(f'{zippath.absolute()}: Extracted all files')

        elif zippath.suffix.lower() == '.7z':
            # Extract all child archives from the main one
            with py7zr.SevenZipFile(zippath, mode='r') as z:
                logger.info(f'{zippath.name}: Retrieving child archives...')
                files = [f for f in z.getnames() if re.search(r'\.7z$', f)]
                z.extract(targets=files, path=dstpath)
            logger.debug(f'{zippath.absolute()}: Extracted {len(files)} files')

        else:
            raise OSError(f'{zippath.name} is neither a ZIP nor a 7z archive.')
        
    except FileNotFoundError as err:
        if is_encrypted_archive(zippath):
            logger.info(f'{zippath.name}: File is encrypted, decrypting...')
            if decrypt_zipfile(zippath, key):
                return extract_zipfile(zippath, outdir, False, fix_crc)
        else:
            logger.debug(f'Extracting main archive: FileNotFoundError: {err}')
            logger.warning(f'{zippath.name}: File not found')

    except OSError as err:
        logger.debug(f'Extracting main archive: OSError: {err}')
        logger.warning(f'{zippath.name}: Unsupported archive format')

    except zipfile.BadZipFile as err:
        logger.debug(f'Extracting main archive: BadZipFile: {err}')
        logger.error(f'{zippath.name}: Invalid ZIP archive')

    except py7zr.exceptions.Bad7zFile as err:
        logger.debug(f'Extracting main archive: Bad7zFile: {err}')
        logger.error(f'{zippath.name}: Invalid 7-Zip archive')

    except py7zr.exceptions.CrcError as err:
        logger.debug(f'Extracting main archive: CrcError: {err}')
        if fix_crc:
            logger.warning(f'{zippath.name}: Fixing CRC...')
            if fix_crc_error(zippath):
                logger.info(f'{zippath.name}: CRC is fixed')
                return extract_zipfile(zippath, outdir, False)
        logger.fatal(f'{zippath.name}: CRC Error')
    
    return dstpath

# -----------------------------------------------------------------------------

def extract_artifact(zippath: Path, pname: str, outdir: Path, \
                     do_check: bool = False, fix_crc: bool = False):
    """
    Extract a child archive.

    Args:
        zippath (Path): Path to the child archive.
        pname (str): Name of the parent archive.
        outdir (Path): The directory in which to extract files.
        do_check (bool): Check integrity if True (default: False).
        fix_crc (bool) : Try to fix the CRC error if True (default: False).

    Returns:
        int: The number of extracted files.
    """
    files = list_harvested(zippath, pname, outdir, fix_crc)

    if len(files) == 0:
        logger.info(f'{pname}: {zippath.name}: No file to extract')
        return 0

    if len(files) > 10000: # Processing a lot a file takes time
        logger.info(f'{pname}: {zippath.name}: Extracting ' \
            f'{len(files)} harvested files, it may take a while...')
    else:
        logger.info(f'{pname}: {zippath.name}: Extracting ' \
            f'{len(files)} harvested files...')

    # Counter for extracted files
    extracted_files_count = 0

    # Read all the archive data
    data = read_artifact(zippath, pname, fix_crc)

    # For each file in the archive, write them into the correct location
    for srcpath, content in data.items():
        if srcpath not in files:
            continue # Skip unlisted files

        # Build the path of the destination file and create the tree
        dstpath = get_dstpath(files[srcpath], outdir).absolute()
        dstpath.parent.mkdir(mode=0o777, parents=True, exist_ok=True)

        # Write the current file into the correct location
        logger_prefix = f'{pname}: {zippath.name}: '
        write_file(dstpath, content.getbuffer(), logger_prefix)
            
        # If necessary, check the file integrity using the harvested SHA1
        check_integrity(dstpath, files[srcpath].SHA1, pname, do_check)

        # Remove the extracted file from the list
        del files[srcpath]
        extracted_files_count += 1
    
    # Check if there is no remaining files
    if len(files) > 0:
        logger.warning(f'{pname}: {zippath.name}: {len(files)} ' \
            'files from \'GetThis.csv\' were not found')
        for sample in files.keys():
            logger.debug(f'File not found: {sample}')

    return extracted_files_count

# -----------------------------------------------------------------------------

def read_artifact(zippath: Path, pname: str, fix_crc: bool = False): 
    """
    Extracts files from a child archive.

    Args:
        zippath (Path): The path to the child archive.
        pname (str): Name of the parent archive.
        fix_crc (bool) : Try to fix the CRC error if True (default: False).

    Returns:
        dict: A dictionary containing file data from the child archive.
    """

    try:
        # ZIP files
        if zippath.suffix.lower() == '.zip':
            with zipfile.ZipFile(zippath, 'r') as z:
                data = {Path(fn): BytesIO(z.read(fn)) for fn in z.namelist()}

        # 7-Zip file
        elif zippath.suffix.lower() == '.7z':
            with py7zr.SevenZipFile(zippath, mode='r') as z:
                data = {Path(fn): file for fn, file in z.readall().items()}

        # Otherwise
        else:
            raise OSError(f'{zippath.name} is neither a ZIP nor a 7z archive.')

        return data
        
    except FileNotFoundError as err:
        logger.debug(f'Extracting child archive: FileNotFoundError: {err}')
        logger.warning(f'{pname}: {zippath.name}: File not found')

    except OSError as err:
        logger.debug(f'Extracting child archive: OSError: {err}')
        logger.warning(f'{pname}: {zippath.name}: Unsupported archive format')

    except zipfile.BadZipFile as err:
        logger.debug(f'Extracting main archive: BadZipFile: {err}')
        logger.error(f'{zippath.name}: Invalid ZIP archive')

    except py7zr.exceptions.Bad7zFile as err:
        logger.debug(f'Extracting child archive: Bad7zFile: {err}')
        logger.warning(f'{pname}: {zippath.name}: Bad 7-Zip file')

    except py7zr.exceptions.CrcError as err:
        logger.debug(f'Extracting child archive: CrcError: {err}')
        if fix_crc:
            logger.warning(f'{pname}: {zippath.name}: Fixing CRC...')
            if fix_crc_error(zippath):
                logger.info(f'{pname}: {zippath.name}: CRC is fixed')
                return read_artifact(zippath, pname, False)
        logger.fatal(f'{pname}: {zippath.name}: CRC Error')

    return dict()

# -----------------------------------------------------------------------------

def write_file(filepath: Path, data: bytes, logger_prefix: str = ''):
    """
    Write data to a file.

    Args:
        filepath (Path): The path to the file to be written.
        data (bytes): The binary data to be written to the file.
        logger_prefix (str): A prefix for the log messages (default: '').
    """
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
    except OSError as err:
        logger.debug(f'Writing file: OSError: {err}')
        logger.error(f'{logger_prefix}{filepath.name}: File not extracted')

# -----------------------------------------------------------------------------

def get_dstpath(fileinfo: object, outdir: Path):
    """
    Get the destination path for a file based on file information.

    Args:
        fileinfo (pandas.Pandas): File information object.
        outdir (Path): The directory in which to extract files.

    Returns:
        Path: Destination path for the file.
    """
    fn = fileinfo.FullName.strip('\\').split('\\')
    dstpath = Path(fileinfo.ComputerName, 'Volumes', fileinfo.VolumeID, *fn)

    if fileinfo.AttrType != '$DATA': # Extended Attributes
        attr = '$NA' if pandas.isna(fileinfo.AttrType) else fileinfo.AttrType
        dstpath = dstpath.with_name(f'{dstpath.name}:{attr}')

    if not pandas.isna(fileinfo.AttrName): # Alternate Data Stream
        dstpath = dstpath.with_name(f'{dstpath.name}:{fileinfo.AttrName}')

    return outdir / dstpath

# -----------------------------------------------------------------------------

def check_integrity(filepath: Path, sha1: str, pname: str, do_check: bool):
    """
    Check file integrity using SHA-1 hash.

    Args:
        filepath (Path): Path to the file.
        sha1 (str): Expected SHA-1 hash.
        pname (str): Name of the parent archive.
        do_check (bool): Check integrity if True.

    Returns:
        bool: Either the hash is valid or not.
    """
    if not do_check:
        return True
    
    # Compute the SHA1 digest of the given file
    with open(filepath, 'rb') as f:
        digest = hashlib.file_digest(f, 'sha1')
    
    if sha1.upper() == digest.hexdigest().upper():
        return True
    
    logger.error(f'{pname}: {filepath.name}: SHA1 deviation')
    logger.debug(f'Expect {sha1.upper()} but got {digest.hexdigest().upper()}')

    return False

# -----------------------------------------------------------------------------

def is_encrypted_archive(zippath: Path):
    """
    Check if a file with the '.p7b' extension exists and is not a directory.

    Args:
        zippath (Path): The original file path.

    Returns:
        bool: True if the '.p7b' file exists, False otherwise.
    """
    encrypted_zippath = zippath.with_name(zippath.name + ".p7b")
    return encrypted_zippath.exists() and encrypted_zippath.is_file()

# -----------------------------------------------------------------------------

def decrypt_zipfile(zippath: Path, key: Path):
    """
    Decrypt a ZIP file using the provided encryption key.

    Args:
        zippath (Path): Path to the encrypted ZIP file.
        key (Path): Path to the encryption key file.

    Returns:
        bool: True if the decryption works, False otherwise.
    """
    if key is False: # Exit case, 'key' is False only if decryption run once
        logger.error(f'{zippath.name}: Decryption failed')
        return False

    if key is None or not key.is_file():
        logger.error(f'{zippath.name}: No key is given, decryption skipped')
        return False

    import shlex, subprocess

    try:
        cwd = zippath.parent
        cmd = ['orc-decrypt', '-k', key, '--output-dir', cwd, cwd]
        result = subprocess.run(cmd, capture_output=True, text=True)

        logger.debug(f'Decryption ended with return code {result.returncode}')

        stdout = result.stdout.strip('\n')
        stderr = result.stderr.strip('\n')
        
        if stdout:
            for stdout_line in stdout.split('\n'):
                logger.debug(stdout_line)
        
        if stderr:
            log_pattern = r'\[[^\]]+\] (?P<log_level>\w+)[\s-]+(?P<message>.*)'
            for stderr_line in stderr.split('\n'):
                match = re.match(log_pattern, stderr_line)
                if match:
                    log_level = match.group('log_level').lower()
                    message = match.group('message')
                    if hasattr(logger, log_level):
                        getattr(logger, log_level.lower())(message)
                    else:
                        logger.debug(f'{log_level} - {message}')
                else:
                    logger.debug(stderr_line)
        
    except FileNotFoundError as err:
        logger.debug(f'Decrypting archive: FileNotFoundError: {err}')
        logger.error(f'{zippath.name}: The tool orc-decrypt is not ' \
            'installed, decryption skipped')
        return False

    return True

# -----------------------------------------------------------------------------

def fix_crc_error(zippath: Path):
    """
    Try to fix the CRC error on a 7-Zip archive using a Bash workaround.

    Args:
        zippath (Path): Path to the corrupted archive.

    Returns:
        bool: True if the fix works, False otherwise.
    """
    import shlex, subprocess
    
    cmd = Path(__file__).with_name('fixCRCerror.sh')
    result = subprocess.run([cmd, zippath], capture_output=True, text=True)

    logger.debug(f'CRC fix ended with return code {result.returncode}')

    stdout = result.stdout.strip('\n')
    stderr = result.stderr.strip('\n')
    
    if stdout:
        for stdout_line in stdout.split('\n'):
            logger.debug(f'{zippath.name}: {stdout_line}')
    
    if stderr:
        for stderr_line in stderr.split('\n'):
            logger.error(f'{zippath.name}: {stderr_line}')
        return False

    return True

# -----------------------------------------------------------------------------

def list_harvested(zippath: Path, pname: str, outdir: Path, fix_crc: bool):
    """
    List files harvested from a DFIR-ORC child archive.

    Args:
        zippath (Path): Path to the DFIR-ORC child archive.
        pname (str): Name of the parent archive.
        outdir (Path): The directory in which to extract files.
        fix_crc (bool) : Try to fix the CRC error if True.

    Returns:
        dict: The files list.
    """
    files = dict()  # Initialize an empty dictionary for files

    try:
        # Read the file 'GetThis.csv' stored in the archive
        dtype = {'SampleName': str, 'AttrType': str, 'AttrName': str}
        msg = 'Reading CSV'

        # Data from the file 'GetThis.csv'
        items = None

        # ZIP files
        if zippath.suffix.lower() == '.zip':
            with zipfile.ZipFile(zippath, 'r') as z:
                names = z.namelist()
                msg += f' among {len(names)} other files'
                msg += ', it may take a while' if len(names) > 10000 else ''
                if 'GetThis.csv' in names:
                    logger.info(f'{pname}: {zippath.name}: {msg}...')
                    data = BytesIO(z.read('GetThis.csv'))
                    items = pandas.read_csv(data, dtype=dtype)

        # 7-Zip file
        elif zippath.suffix.lower() == '.7z':
            with py7zr.SevenZipFile(zippath, mode='r') as z:
                names = z.getnames()
                msg += f' among {len(names)} other files'
                msg += ', it may take a while' if len(names) > 10000 else ''
                if 'GetThis.csv' in names:
                    logger.info(f'{pname}: {zippath.name}: {msg}...')
                    data = z.read(['GetThis.csv'])['GetThis.csv']
                    items = pandas.read_csv(data, dtype=dtype)

        # Otherwise
        else:
            raise OSError(f'{zippath.name} is neither a ZIP nor a 7z archive.')

        # Build the file list
        if items is not None:
            logger.debug(f'Found files: {len(items)} ({zippath.absolute()})')

            # Save files statistics stored in 'GetThis.csv'
            update_fs_stat(items, outdir)

            # Keep only harvested files
            for item in items.itertuples():
                if not pandas.isna(item.SampleName):
                    files[Path(*item.SampleName.split('\\'))] = item
            
        logger.debug(f'Harvested files: {len(files)} ({zippath.absolute()})')

    except KeyError as err:
        logger.debug(f'Listing harvested files: KeyError: {err}')
        logger.warning(f'{pname}: {zippath.name}: CSV file not found')

    except OSError as err:
        logger.debug(f'Listing harvested files: OSError: {err}')
        logger.warning(f'{pname}: {zippath.name}: Unsupported archive format')

    except zipfile.BadZipFile as err:
        logger.debug(f'Extracting main archive: BadZipFile: {err}')
        logger.error(f'{zippath.name}: Invalid ZIP archive')

    except py7zr.exceptions.Bad7zFile as err:
        logger.debug(f'Listing harvested files: Bad7zFile: {err}')
        logger.warning(f'{pname}: {zippath.name}: Bad 7-Zip file')

    except py7zr.exceptions.CrcError as err:
        logger.debug(f'Listing harvested files: CrcError: {err}')
        if fix_crc:
            logger.warning(f'{pname}: {zippath.name}: Fixing CRC...')
            if fix_crc_error(zippath):
                logger.info(f'{pname}: {zippath.name}: CRC is fixed')
                return list_harvested(zippath, pname, outdir, False)
        logger.fatal(f'{zippath.name}: CRC Error')

    return files

# -----------------------------------------------------------------------------

def update_fs_stat(items: pandas.DataFrame, outdir: Path):
    """
    Update filesystem statistics from a DataFrame and export to CSV files.

    Args:
        items (pd.DataFrame): DataFrame containing file system information.
        outdir (Path): Path to the output directory for the CSV files.
    """
    fs_stat = dict()
    dtype = {'attribute_names': str, 'is_allocated': bool}

    # Process each item and create events
    for item in items.itertuples():

        if item.ComputerName not in fs_stat:
            fs_stat[item.ComputerName] = list()

        fn = item.FullName.strip('\\').split('\\')
        filename = Path(item.VolumeID, *fn).as_posix()
        base_event = {
            'datetime': None,
            'timestamp_desc': None,
            'source': 'ORC',
            'source_long': 'DFIR-ORC GetThis',
            'message': f'OS:{filename} Type: {item.ContentType}',
            'parser': 'filestat',
            'display_name': f'OS:{filename}',
            'tag': '-',
            'data_type': 'fs:stat',
            'attribute_names': item.AttrName,
            'file_entry_type': item.ContentType,
            'file_size': item.SizeInBytes,
            'file_system_type': 'OS',
            'filename': f'{filename}',
            'group_identifier': '-',
            'inode': '-',
            'is_allocated': not pandas.isna(item.SampleName),
            'mode': '-',
            'number_of_links': '-',
            'owner_identifier': '-',
            'md5': item.MD5,
            'sha1': item.SHA1,
            'sha256': item.SHA256,
        }

        # Add events for different timestamps directly to the dict
        for timestamp, desc in [
            (item.CreationDate, 'Creation Time'),
            (item.LastModificationDate, 'Content Modification Time'),
            (item.LastAccessDate, 'Last Access Time'),
            (item.LastAttrChangeDate, 'Metadata Modification Time'),
        ]:
            if timestamp:
                event = base_event.copy()
                event['datetime'] = timestamp
                event['timestamp_desc'] = desc
                fs_stat[item.ComputerName].append(event)

    for hostname, data in fs_stat.items():
        if data:  # Skip if there's no data for the hostname
            filepath = Path(outdir, hostname, 'Timelines', 'fs:stat.csv')
            filepath.parent.mkdir(parents=True, exist_ok=True)

            # Create a DataFrame from the data
            df = pandas.DataFrame(data)

            # Read the existing CSV (if exists) into a DataFrame
            if filepath.exists():
                existing_df = pandas.read_csv(filepath, dtype=dtype)
                df = pandas.concat([existing_df, df], ignore_index=True)
                df = df.drop_duplicates()
            
            # Write to the CSV file
            df.to_csv(filepath, mode='w', index=False, header=True)

# =============================================================================
# -----------------------------------------------------------------------------
# =============================================================================

if __name__ == '__main__':

    # Declare the argument parser and the logging configuration
    args = get_args()
    define_console_logging(args.debug)
    define_file_logging(Path(f'{TOOLNAME}.log').absolute(), args.debug)

    # Ensure paths are absolutes
    outdir = Path(args.outdir)
    key = Path(args.key) if args.key else None

    # Main counter for extracted files
    main_count = 0

    # For each main archive, extract data into a temp directory
    for parent_zippath in list_zippaths(args.zippaths, args.jsonfiles):
        tmpdir = extract_zipfile(parent_zippath, outdir, key, args.fix_crc)

        # Counter for extracted files
        count = 0

        # For each child archive, extract and store data
        child_zippaths = list(tmpdir.glob('*.zip')) + list(tmpdir.glob('*.7z'))
        for child_zippath in child_zippaths:
            count += extract_artifact(child_zippath, parent_zippath.name, \
                                      outdir, args.check, args.fix_crc)

        # Update the main counter
        counter = f"{count} file{'s' if count>1 else ''}"
        logger.info(f'{parent_zippath.name}: Done, {counter} extracted')
        main_count += count

        # Clean up the temporary files
        if tmpdir.is_dir():
            shutil.rmtree(tmpdir)

    # End of the extraction
    counter = f"{main_count} file{'s' if main_count>1 else ''}"
    logger.info(f'Finished, {main_count} extracted')
