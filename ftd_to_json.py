import os
import json
from ttp import ttp
from colors import bcolors


def convert(template_path: str, configuration_path: str):
    template_exist = os.path.exists(template_path)
    configuration_exists = os.path.exists(configuration_path)
    if template_exist and configuration_exists:
        with open(configuration_path) as file:
            configuration = file.read()
        with open(template_path) as file:
            template = file.read()
        parser = ttp(configuration, template)
        parser.parse()
        data_dict = parser.result()[0][0]
        json_data = json.dumps(data_dict, indent=4)
        with open("result.json", "w") as f:
            f.write(json_data)
        print(
            bcolors.OKGREEN
            + f"File {configuration_path.split('/')[-1]} converted to result.json"
            + bcolors.ENDC
        )


if __name__ == "__main__":
    configuration_path = "firepower_config.txt"
    template_path = "ttp_v6.txt"
    convert(template_path, configuration_path)
