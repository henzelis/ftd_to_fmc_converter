# Cisco FTD to FMC recovery tool 
Orphan FTD configuration to FMC converting tool.

If your FMC is died some day and you have only FTD without any management this tool may be yours last hope instrument to recover configuration and put it back to new FMC.

What is supported for now:
 - Security zone migration;
 - Network object migration;
 - Service objects migration;
 - Access rules and Policies migration;
 - Object NAT migration;

Limitation:
FTD LINA configuration not containing SNORT rule information and information related to SNORT engine will not be recovered.

## TODO:
NAT parsing should be added in the future releases

To make it work you need to do next steps:
1) Connect using SSH to yours orphan FTD with was under the FMC management;
2) Enter LINA CLI using 'system support diagnostic-cli' command;
3) Switch to enabled mode by entering 'enable' command;
4) Password is empty;
5) Collect all the configuration of the LINA with 'show running-config';
6) Save output like text file in the folder with the script. Name this file as 'firepower_config.txt';
7) Run script ftd_to_fmc_convert.py or if you are using Windows just run 'run_converter.cmd';
First run of the script should be done on the PC with Internet access to download port and protocol binding information from IANA site. After the first run files will be cached and reused by next run.
On a new FMC you need to create user with API privileges and input this credentials during the software execution.


