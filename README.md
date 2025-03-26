# DFIR-ORC to Tree

The main goal to **orc2tree** is to extract the files harvested by the DFIR-ORC tool (https://dfir-orc.github.io/) and reorganizes them according to their original location on the disk. The tool also parse outputs from ORC's commands to provide usable data for investigative purposes. The script uses the metadata from "GetThis.csv" populated by the DFIR-ORC tool to reconstruct the tree structure of the original disk(s) in a directory named "Volumes" and the results of the ORC's commands in various directories alongside it. The output provided the "Volumes" directory might be used in different forensics tools (i-e: Plaso, yara, autopsy, etc.).

<div align="center">
  <img alt="Logo orc2tree" height="256px" src="./orc2tree-logo.png">
</div>

The tool [DFIR-ORC](https://dfir-orc.github.io/) will gather files (evtx, winreg, suspicious files) from different commands. To avoid overwriting, the files are renamed in the form `<VolumeID>_<ParentFRN>_<FRN>_<AttrID>_<FileName>_{<UUID>}.data` and all placed in a single 7-Zip archive (or ZIP). Directory tree is lost during the process. For example :

```
Event.7z
├── evtx
│   ├── 36DA2C4BDA2C0A27_10000000009E5_100000000E576_0_Application.evtx_{00000000-0000-0000-0000-000000000000}.data
│   ├── 36DA2C4BDA2C0A27_10000000009E5_500000005AF3A_0_Security.evtx_{00000000-0000-0000-0000-000000000000}.data
│   ├── 36DA2C4BDA2C0A27_10000000009E5_2000000000025_4_Setup.evtx_{00000000-0000-0000-0000-000000000000}.data
│   │
│   │   [...]
│   │
│   └── 36DA2C4BDA2C0A27_10000000009E5_400000005AF5B_3_System.evtx_{00000000-0000-0000-0000-000000000000}.data
└── GetThis.csv
```

In addition, the CSV file `GetThis.csv`, present in each of the harvested archives, gathers information specific to each file, including absolute paths and metadata. For example :

```csv
ComputerName,VolumeID,ParentFRN,FRN,FullName,SampleName,SizeInBytes,MD5,SHA1,FindMatch,ContentType,SampleCollectionDate,CreationDate,LastModificationDate,LastAccessDate,LastAttrChangeDate,FileNameCreationDate,FileNameLastModificationDate,FileNameLastAccessDate,FileNameLastAttrModificationDate,AttrType,AttrName,AttrID,SnapshotID,SHA256,SSDeep,TLSH,YaraRules
"WIN-C23B9AE4",0x36DA2C4BDA2C0A27,0x00010000000009E5,0x000100000000E576,"\Windows\System32\winevt\Logs\Application.evtx","evtx\36DA2C4BDA2C0A27_10000000009E5_100000000E576_0_Application.evtx_{00000000-0000-0000-0000-000000000000}.data",512036864,E4C12597F822C7974020F760C33556D2,5492495B0E2A6D518949C6A95508167686B1FDD9,"Name matches *.evtx, Header=456c6646696c65","data",2022-06-29 08:15:24.734,2014-10-13 11:05:06.667,2022-06-29 07:55:50.096,2014-10-13 11:05:06.667,2022-06-29 07:55:50.096,2014-10-13 11:05:06.667,2014-10-13 11:05:06.667,2014-10-13 11:05:06.667,2014-10-13 11:05:06.667,"$DATA",,0,{00000000-0000-0000-0000-000000000000},,,,
"WIN-C23B9AE4",0x36DA2C4BDA2C0A27,0x00010000000009E5,0x0002000000000025,"\Windows\System32\winevt\Logs\Setup.evtx","evtx\36DA2C4BDA2C0A27_10000000009E5_2000000000025_4_Setup.evtx_{00000000-0000-0000-0000-000000000000}.data",1052672,6A346D6FAC62F3FAC1990B9CFAE96DF2,2ACE3789A68F63311C0143691D8FF742F8BCCE37,"Name matches *.evtx, Header=456c6646696c65","data",2022-06-29 08:15:24.734,2014-10-13 11:07:26.833,2022-04-22 19:32:59.661,2014-10-13 11:07:26.833,2022-04-22 19:32:59.661,2014-10-13 11:07:26.833,2014-10-13 11:07:26.833,2014-10-13 11:07:26.833,2014-10-13 11:07:26.833,"$DATA",,4,{00000000-0000-0000-0000-000000000000},,,,
"WIN-C23B9AE4",0x36DA2C4BDA2C0A27,0x00010000000009E5,0x0002000000006115,"\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx","evtx\36DA2C4BDA2C0A27_10000000009E5_2000000006115_4_Microsoft-Windows-Windows_Firewall_With_Advanced_Security%4ConnectionSecurity.evtx_{00000000-0000-0000-0000-000000000000}.data",69632,BBE7FE15D335DF6B0C993017B1EB5FE7,FBA95C044ED3BA22FA4EF501CEF7C0865F3B5CAB,"Name matches *.evtx, Header=456c6646696c65","data",2022-06-29 08:15:24.734,2014-10-13 11:05:13.843,2014-10-13 11:07:28.627,2014-10-13 11:05:13.843,2014-10-13 11:07:28.627,2014-10-13 11:05:13.843,2014-10-13 11:05:13.843,2014-10-13 11:05:13.843,2014-10-13 11:05:13.843,"$DATA",,4,{00000000-0000-0000-0000-000000000000},,,,
"WIN-C23B9AE4",0x36DA2C4BDA2C0A27,0x00010000000009E5,0x000500000005AF3A,"\Windows\System32\winevt\Logs\Security.evtx","evtx\36DA2C4BDA2C0A27_10000000009E5_500000005AF3A_0_Security.evtx_{00000000-0000-0000-0000-000000000000}.data",512036864,A06C060C1FAE63271AF23E6EC2C56CCD,4D45CC4E44A0EA0FEC58FD253DB388770F08DF4B,"Name matches *.evtx, Header=456c6646696c65","data",2022-06-29 08:15:24.734,2014-10-13 11:05:06.667,2022-06-29 07:55:50.018,2019-07-15 13:43:39.891,2022-06-29 07:55:50.018,2019-07-15 13:43:39.891,2019-07-15 13:43:41.623,2019-07-15 13:43:39.891,2019-07-15 13:43:41.623,"$DATA",,0,{00000000-0000-0000-0000-000000000000},,,,
"WIN-C23B9AE4",0x36DA2C4BDA2C0A27,0x00010000000009E5,0x000400000005AF5B,"\Windows\System32\winevt\Logs\System.evtx","evtx\36DA2C4BDA2C0A27_10000000009E5_400000005AF5B_3_System.evtx_{00000000-0000-0000-0000-000000000000}.data",49352704,3661070B93F5BDDC73BB843628699CF9,EB46032FE6BD207246C468CE9A566E0A258721B0,"Name matches *.evtx, Header=456c6646696c65","data",2022-06-29 08:15:24.734,2014-10-13 11:05:06.651,2022-06-29 07:55:50.003,2019-07-15 18:15:57.418,2022-06-29 07:55:50.003,2019-07-15 18:15:57.418,2019-07-15 18:15:57.683,2019-07-15 18:15:57.418,2019-07-15 18:15:57.683,"$DATA",,3,{00000000-0000-0000-0000-000000000000},,,,
```

Once the data gathered by DFIR_ORC, **orc2tree** will extract all of these files (evtx, hives, user registers, suspicious files harvested, etc.) and will use the CSV `GetThis.csv` to rebuild the directory tree.

## Installation

The project requires the use of _Python 3_, the development and testing having been done with _Python 3.10_. Two external libraries are required : `py7zr` for reading and extracting 7-Zip archives, `pandas` for CSV reading and `coloredlogs` for pretty output. Once you have cloned the repository, the best way to install _orc2tree_ is to build the Docker image.

```bash
docker build -t orc2tree:latest .
```

If you prefer not to use Docker, you can run _orc2tree_ directly on your local machine. Ensure that `7z` is installed (package `p7zip-full` for Debian/Ubuntu or `p7zip` for MacOS). It is recommended to use a virtual environment to manage dependencies. 

```bash
python3 -m venv ./venv-orc2tree
source venv-orc2tree/bin/activate
pip3 install -r requirements.txt
```

## Usage

```
usage: orc2tree.py [-h] [--zip ZIPFILE [ZIPFILE ...]] [--json JSONFILE [JSONFILE ...]] [--outdir DIRNAME] [--check] [--key KEYFILE] [--fix-crc] [--debug]

extracts DFIR archives harvested by the DFIR-ORC tool (https://dfir-orc.github.io) and reorganizes them according to their original location on the disk. The script uses the metadata from "GetThis.csv" populated by the DFIR-ORC tool to reconstruct the tree of the original disk(s).

options:
  -h, --help                        show this help message and exit
  --zip ZIPFILE [ZIPFILE ...]       one or more archives from DFIR-ORC (7-Zip or ZIP)
  --json JSONFILE [JSONFILE ...]    the DFIR-ORC Execution Outline
  --outdir DIRNAME                  the directory in which to extract files (default: ".")
  --check                           check for SHA1 of extracted files
  --key KEYFILE                     the private key for encrypted archives
  --fix-crc                         use an external script to resolve CRC errors
  --debug                           enable debug output
```

The following examples run with Docker, but local use (via _venv_) is identical.

**Basic Help Command**

```bash
docker run -it --rm -v orc2tree:latest --help
```

**Process a JSON file from DFIR-ORC outputs**

```bash
docker run -it --rm -v $PWD:/data orc2tree:latest --json <JSONFILE>
```

**Extract data from a corrupted archive (CRC error)**

```bash
docker run -it --rm -v $PWD:/data orc2tree:latest --zip <ZIPFILE> --fix-crc
```

## Future Improvements

### Handle CRC errors

When the CRC check fails, `py7zr` raises an `CRCError` exception and stops file extraction. As a result, the extracted data is incomplete. However, the data is present in the archive created by DFIR-ORC and can be extracted from 7z CLI and GUI tools. This problem is well known (https://github.com/miurahr/py7zr/issues/359) and seems to be caused by the empty files that are sometimes included in archives. 

The `orc2tree` script will ignore these errors and display a error message before continuing its execution. A temporary workaround for these errors is to use 7z CLI to extract the data and recreate an uncorrupted archive. The `fixCRCerror.sh` script takes care of this operation and can be automatically called by `orc2tree.py` with `--fix-crc`.

### Unconsolidated information

- Directories and files MACB (dates)
- Permissions
- Symlink between directories or files
- MFT reference (cluster/sector will not match)
- Outputs from ORC internal commands

## Contributing

Contributions are welcome. If you'd like to add new analysis modules, enhance existing scripts, or report issues, please follow these steps:

- Fork the repository
- Create a new branch for your feature or bug fix
- Make your changes and test them
- Submit a pull request, describing your changes and their purpose

## License

This project is licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1). It grants you certain permissions and responsibilities when using and distributing this software. You are free to modify and distribute this software, either under the terms of the license or under the terms of any later version published by the Free Software Foundation. However, this project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Please see the [LICENSE](./LICENSE) file for more details.
