from ttp import ttp
import csv
import os
import json
from colors import bcolors

# configuration_path = "D:\Google_Drive\Alesta\KODA\ASA-5505_SH_RUNN.txt"
# configuration_path = "D:\Python\play_with_something\ASA_converter\/firepower_config.txt"
configuration_path = "D:\Python\play_with_something\ASA_converter\/nszu_ftd_config.txt"
# configuration_path = "D:\Python\play_with_something\ASA_converter\/2110_run.txt"
template_path = "D:\Python\play_with_something\ASA_converter\/ttp_test_v5.txt"


def convert(template_path: str, configuration_path: str):
    template_exist = os.path.exists(template_path)
    configuration_exists = os.path.exists(configuration_path)
    if template_exist and configuration_exists:
        with open(configuration_path, 'r') as file:
            configuration = file.read()
        with open(template_path, 'r') as file:
            template = file.read()
        parser = ttp(configuration, template)
        parser.parse()
        data_dict = parser.result()[0][0]
        json_data = json.dumps(data_dict, indent=4)
        # print(json_data)
        with open("result.json", "w") as f:
            f.write(json_data)
        print(bcolors.OKGREEN + f"File {configuration_path.split('/')[-1]} converted to result.json" + bcolors.ENDC)


# convert(template_path, configuration_path)

# with open("result.json", "w") as f:
#     f.write(json_data)

# Create a CSV file for writing
# with open('access_list.csv', 'w', newline='') as csv_file:
#     # Create a CSV writer
#     csv_writer = csv.writer(csv_file)
#
#     # Write the header row
#     csv_writer.writerow(['Access List', 'Action', 'Service', 'Source Object', 'Destination Object', 'Destination Service'])
#     csv_writer.writerow([name, enabled, action, VlanTags, sourceZones, destZones, sourceNetworks, destNetworks, sourcePorts, destPorts, Applications, URLs, users,comments,ipsPolicy, variableSet, filePolicy, logBegin, logEnd, sendEventsToFMC, syslogConfig
# ])
#
#     # Iterate through the JSON data and write rows to the CSV
#     for access_list, entries in data_dict['access-lists'].items():
#         for entry in entries:
#
#             action = entry.get('action', '')
#             service = entry.get('service', '')
#             src_object = entry.get('src_object', '')
#             dst_object = entry.get('dst_object', '')
#             dst_service = entry.get('dst_service', '')
#
#             # Write the row
#             csv_writer.writerow([access_list, action, service, src_object, dst_object, dst_service])
#
# print("CSV conversion complete. Check 'access_list.csv'.")



