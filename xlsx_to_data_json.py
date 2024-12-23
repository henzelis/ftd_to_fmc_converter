import pandas as pd
import json

file_path = "object_data.xlsx"
sheet_name = "host"
result_file = "result.json"

data_dict = {
    "objects": {
        "network-objects": {}
    }
}


def convert_xlsx_to_json(file_path, result_file_name):
    xlsx_file = file_path
    df = pd.read_excel(xlsx_file)
    object_names = df["objects"]
    for obj in object_names:
        print(obj)
        ip_add = list(df[df["objects"].str.contains(obj)]["hosts"])[0]
        print(ip_add)
        data_dict["objects"]["network-objects"][obj] = {
            "value": ip_add,
            "type": "host"
        }
    json_data = json.dumps(data_dict, indent=4)
    with open(result_file_name, "w") as f:
        f.write(json_data)
    print(f"File {file_path} successfully converted to {result_file_name} ")


convert_xlsx_to_json(file_path, result_file)
print('end')
