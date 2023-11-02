import fireREST
import json
import time
import ipaddress
import requests
import xmltodict
import os
import sys
import ftd_to_json
from colors import bcolors
from getpass import getpass

configuration_path = "firepower_config.txt"
template_path = "ttp_v5.txt"

ftd_to_json.convert(template_path, configuration_path)
action = "create_all"
# action = "delete_all"


if os.path.exists('fmc_creds.json'):
    print('Credential file, fmc_creds.json found!')
    with open('fmc_creds.json') as fmc_creads:
        login_data = json.load(fmc_creads)
    fmc_ip = login_data.get('fmc_ip')
    fmc_user = login_data.get('fmc_user')
    fmc_password = login_data.get('fmc_password')
    if not fmc_ip or not fmc_user or not fmc_password:
        sys.exit('File fmc_creds.json not contain required credentials or IP data, please delete the file and rerun '
                 'program')
else:
    while True:
        fmc_ip = input('Please provide FMC IP address: ')
        try:
            fmc_ip_address = ipaddress.ip_address(fmc_ip)
            if fmc_ip_address:
                break
        except ValueError:
            print(bcolors.FAIL + 'ERROR: Wrong IP address format or host ip provided' + bcolors.ENDC)
            continue
    fmc_user = input('Please provide FMC API capable username: ')
    fmc_password = getpass('Please provide FMC API capable user password: ')

    fmc_creds_dict = {'fmc_ip': fmc_ip, 'fmc_user': fmc_user, 'fmc_password': fmc_password}
    fmc_creds_json = json.dumps(fmc_creds_dict, indent=4)
    with open('fmc_creds.json', 'w') as creds_file:
        creds_file.write(fmc_creds_json)

fmc = fireREST.FMC(fmc_ip, fmc_user, fmc_password)
print(f'Connected to FMC IP {fmc_ip}')

with open('result.json') as file:
    data = json.load(file)

# fmc.policy.accesspolicy.accessrule.get(container_name='ACP')
# fmc.policy.accesspolicy.accessrule.get(container_name='ACP', name='Portrange')
# acp_create_data = {'name': 'acp_test', 'description': 'ACP Test', 'defaultAction': {'action': 'BLOCK'}}
# fmc.policy.accesspolicy.create(acp_create_data)
# fmc.policy.accesspolicy.delete(name='acp_test')
# fmc.device.devicerecord.fpphysicalinterface.get()
# fmc.policy.ftdnatpolicy.get(name='NAT_FTD')
# fmc.policy.ftdnatpolicy.autonatrule.get(container_name='NAT_FTD')
# fmc.policy.ftdnatpolicy.manualnatrule.get(container_name='NAT_FTD')


rule_action_dict = {
    'permit': 'ALLOW',
    'deny': 'BLOCK',
    'trust': 'TRUST',
    'monitor': 'MONITOR'
}

icmp_type_dict = {
    'echo-reply': '0',
    'unreachable': '3',
    'source-quench': '4',
    'redirect': '5',
    'alternate-address': '6',
    'echo': '8',
    'router-advertisement': '9',
    'router-solicitation': '10',
    'time-exceeded': '11',
    'parameter-problem': '12',
    'timestamp-request': '13',
    'timestamp-reply': '14',
    'information-request': '15',
    'information-reply': '16',
    'mask-request': '17',
    'mask-reply': '18',
    'traceroute': '30',
    'conversion-error': '31',
    'mobile-redirect': '32',
}


def get_port_map():
    if os.path.exists('port-map.xml'):
        print('port-map.xml exists, using it.')
        with open('port-map.xml') as portmapdata:
            data_dict = xmltodict.parse(portmapdata.read())
    else:
        print('NO port-map.xml file, creating it...')
        iana_data = requests.get(
            url='https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml')
        with open('port-map.xml', 'wb') as f:
            f.write(iana_data.content)
        data_dict = xmltodict.parse(iana_data.text)
    port_map = {}
    for i in data_dict['registry']['record']:
        # print(f"Name: {i.get('name')}, Protocol: {i.get('protocol')}, Number: {i.get('number')}")
        try:
            number = i['number']
            if number == "None":
                continue
            port_map[i.get('name')] = i.get('number')
        except Exception as e:
            # print(e)
            pass
    return port_map


def get_protocol_map():
    if os.path.exists('protocol-map.xml'):
        print('protocol-map.xml exists, using it.')
        with open('protocol-map.xml') as protocol_data:
            data_dict = xmltodict.parse(protocol_data.read())
    else:
        print('No protocol-map.xml file, creating ...')
        iana_data = requests.get(
            url='https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml'
        )
        with open('protocol-map.xml', 'wb') as f:
            f.write(iana_data.content)
        data_dict = xmltodict.parse(iana_data.text)
    protocol_map = {}
    for i in data_dict['registry']['registry']['record']:
        # print(i)
        if i.get('name'):
            protocol_map[i.get('name').lower()] = i.get('value')
    return protocol_map


def is_range(range_data: str):
    """
    Check if data is a range, for example 60-1024 is range, i-1024 is not
    :param range_data: string with data
    :return: result of verification - True of False
    """
    isrange = False
    try:
        [int(i) for i in range_data.split('-')]
        isrange = True
        return isrange
    except Exception:
        return isrange


def is_present(field: str, obj: list):
    """
    Check if field present in the object
    :param field: name of the filed
    :param obj: object = list of dictionaries
    :return: result of check - True of False
    """
    present_result = False
    for i in obj:
        if field in i.keys():
            present_result = True
    return present_result


# fmc.policy.accesspolicy.accessrule.create(data=policy_json, container_name='ACP')
# fmc.object.application.get(name='ICMP')


class FMCobject:
    def __init__(self, name=None, value=None, port_name=None, port_number=None, protocol=None, obj_type=None,
                 obj_id=None):
        self.object_template = None
        self.name = name
        self.value = value
        self.port_name = port_name
        self.port_number = port_number
        self.protocol_name = protocol
        self.obj_type = obj_type
        self.obj_id = obj_id
        self.net_obj_template = {
            'name': self.name,
            'value': self.value,
        }
        self.protocol_data = {
            'name': self.port_name,
            'port': self.port_number,
            'protocol': self.protocol_name}
        self.nat_policy = {
            'name': self.name
        }

    def create_nat_policy(self):
        try:
            response = fmc.policy.ftdnatpolicy.create(data=self.nat_policy)
            print(bcolors.OKGREEN + f'FTD NAT Policy Created: {self.name} + bcolors.ENDC')
        except Exception as e:
            print(bcolors.WARNING + str(e) + bcolors.ENDC)
            return e
        return response

    def delete_nat_policy(self):
        try:
            responce = fmc.policy.ftdnatpolicy.delete(name=self.name)
            return responce
        except Exception as e:
            return e

    def create_port_object(self):
        respose = fmc.object.protocolportobject.create(data=self.protocol_data)
        return respose

    def delete_port_object(self):
        responce = fmc.object.protocolportobject.delete(name=self.name)
        return responce

    def create_host_object(self):
        response = fmc.object.host.create(data=self.net_obj_template)
        return response

    def create_network_object(self):
        response = fmc.object.network.create(data=self.net_obj_template)
        return response

    def del_host_object(self):
        response = fmc.object.host.delete(name=self.name)
        return response

    def del_network_object(self):
        response = fmc.object.network.delete(name=self.name)
        return response

    def get_object_type(self):
        try:
            self.obj_type = fmc.object.network.get(name=self.name)['type']
            return self.obj_type
        except Exception as e:
            self.obj_type = e
            pass
        try:
            self.obj_type = fmc.object.host.get(name=self.name)['type']
            return self.obj_type
        except Exception as e:
            self.obj_type = e
            pass
        try:
            self.obj_type = fmc.object.securityzone.get(name=self.name)['type']
            return self.obj_type
        except Exception as e:
            print(bcolors.WARNING + f'Resource with name {self.name} does not exist' + bcolors.ENDC)
            return e

    def get_object_id(self):
        if self.obj_type == 'Network':
            self.obj_id = fmc.object.network.get(name=self.name)['id']
        elif self.obj_type == 'Host':
            self.obj_id = fmc.object.host.get(name=self.name)['id']
        elif self.obj_type == 'SecurityZone':
            self.obj_id = fmc.object.securityzone.get(name=self.name)['id']
        if self.obj_id:
            return self.obj_id

    def get_object_json(self):
        self.obj_type = self.get_object_type()
        self.obj_id = self.get_object_id()
        self.object_template = {
            'name': self.name,
            'id': self.obj_id,
            'type': self.obj_type
        }
        return self.object_template


def nat_rules(action: str, nat_policy_name: str, source_data=None):
    if action == 'create_auto_nat':
        for obj in source_data['nat']['object-nat']:
            try:
                obj_path = source_data.get('nat').get('object-nat').get(obj)
                nat_object = {'type': 'FTDAutoNatRule'}
                if 'nat_type' in obj_path.keys():
                    nat_type = obj_path["nat_type"].upper()
                    nat_object['natType'] = nat_type
                    origin_network = obj
                    transl_network = obj_path.get("translated_network")
                    source_zone = obj_path.get("src_intf")
                    dst_zone = obj_path.get("dst_intf")
                    fmc_object_orign = FMCobject(name=origin_network)
                    origin_network_json = {'originalNetwork': fmc_object_orign.get_object_json()}
                    nat_object.update(origin_network_json)
                    if transl_network and transl_network != 'any':
                        fmc_object_transl = FMCobject(name=transl_network)
                        transl_network_json = {'translatedNetwork': fmc_object_transl.get_object_json()}
                        nat_object.update(transl_network_json)
                    if source_zone and source_zone != 'any':
                        fmc_object_src_zone = FMCobject(name=source_zone)
                        src_zone_json = {'sourceInterface': fmc_object_src_zone.get_object_json()}
                        nat_object.update(src_zone_json)
                    if dst_zone and dst_zone != 'any':
                        fmc_object_dst_zone = FMCobject(name=dst_zone)
                        dst_zone_json = {'destinationInterface': fmc_object_dst_zone.get_object_json()}
                        nat_object.update(dst_zone_json)
                    fmc.policy.ftdnatpolicy.autonatrule.create(container_name=nat_policy_name, data=nat_object)
                    print(bcolors.OKGREEN + f'Auto Nat Rule Created {obj}' + bcolors.ENDC)
            except Exception as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
                pass
    else:
        return None


port_map = get_port_map()
protocol_map = get_protocol_map()


def do(do_func):
    for obj in data['object-groups']['object-service-groups']:
        # ################################## CREATE PORT OBJECTS ##############################################
        if "create_port_objects" in do_func:
            obj_port_name = obj
            try:
                obj_protocol = data['object-groups']['object-service-groups'][obj]['protocol']
                obj_port_number = data['object-groups']['object-service-groups'][obj]['protocol-port-objects'][0]
            except Exception as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
                continue
            if not obj_port_number.isdigit() and not is_range(obj_port_number):
                obj_port_number = port_map[obj_port_number.replace('imap4', 'imaps')]
            fmc_object = FMCobject(port_name=obj_port_name, port_number=obj_port_number, protocol=obj_protocol)
            try:
                fmc_object.create_port_object()
                print(
                    bcolors.OKGREEN + f'Port Object Created - {obj_port_name} - {obj_port_number} - {obj_protocol}' + bcolors.ENDC)
            except fireREST.exceptions.GenericApiError as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
                continue
        if "del_port_objects" in do_func:
            fmc_object = FMCobject(name=obj)
            try:
                fmc_object.delete_port_object()
                print(bcolors.OKGREEN + f'Port Object Deleted - {obj}' + bcolors.ENDC)
            except Exception as e:
                print(bcolors.WARNING + obj + ': not deleted ' + str(e) + bcolors.ENDC)
                pass
    for obj in data['objects']['network-objects']:
        obj_type = data['objects']['network-objects'][obj]['type']
        if obj_type == 'host':
            obj_name = obj
            obj_value = data['objects']['network-objects'][obj]['value']
            fmc_object = FMCobject(name=obj_name, value=obj_value)
            # ################################## CREATE HOST OBJECTS ##############################################
            if "create_host_objects" in do_func:
                try:
                    fmc_object.create_host_object()
                    print(bcolors.OKGREEN + f'Host Object Created - {obj_name} - {obj_value}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError as e:
                    print(bcolors.WARNING + str(e) + bcolors.ENDC)
                    continue
            # ################################## DELETE HOST OBJECTS ##############################################
            if "del_host_objects" in do_func:
                try:
                    fmc_object.del_host_object()
                    print(bcolors.OKGREEN + f'Host Object Deleted - {obj_name} - {obj_value}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError as e:
                    print(bcolors.WARNING + obj + ': not deleted ' + str(e) + bcolors.ENDC)
                    continue
        if obj_type == 'network':
            obj_name = obj
            obj_value = data['objects']['network-objects'][obj]['value']
            fmc_object = FMCobject(name=obj_name, value=obj_value)
            # ################################## CREATE NETWORK OBJECTS ##############################################
            if "create_network_objects" in do_func:
                try:
                    fmc_object.create_network_object()
                    print(bcolors.OKGREEN + f'Network Object Created - {obj_name}  {obj_value}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError as e:
                    print(bcolors.WARNING + str(e) + bcolors.ENDC)
                    continue
            # ################################## DELETE NETWORK OBJECTS ##############################################
            if "del_network_objects" in do_func:
                try:
                    fmc_object.del_network_object()
                    print(bcolors.OKGREEN + f'Network Object Deleted - {obj_name} - {obj_value}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError as e:
                    print(bcolors.WARNING + obj + ': not deleted ' + str(e) + bcolors.ENDC)
                    continue
            time.sleep(0.3)
    # ################################## CREATE GROUP NETWORK OBJECTS ##############################################
    if do_func == 'create_group_network_objects':
        for obj in data["object-groups"]["object-network-groups"]:
            if 'FMC_INLINE' not in obj:
                description = data.get("object-groups").get("object-network-groups").get(obj).get("description")
                network_obj = data["object-groups"]["object-network-groups"][obj]["network-objects"]
                obj_name = obj
                named_objects_list = network_obj.get("objects")
                network_obj_list = network_obj.get("networks")
                network_obj_group_data = {'type': 'NetworkGroup', 'name': obj_name}
                if description:
                    network_obj_group_data['description'] = description
                if named_objects_list:
                    objects = []
                    for named_net_obj in named_objects_list:
                        fmc_object_named = FMCobject(name=named_net_obj)
                        object_dict = fmc_object_named.get_object_json()
                        objects.append(object_dict)
                    network_obj_group_data['objects'] = objects
                if network_obj_list:
                    literals = []
                    for network in network_obj_list:
                        network_dict = {}
                        if '/32' in network:
                            network_dict['type'] = 'Host'
                        else:
                            network_dict['type'] = 'Network'
                        network_dict['value'] = network
                        literals.append(network_dict)
                    network_obj_group_data['literals'] = literals
                try:
                    fmc.object.networkgroup.create(network_obj_group_data)
                    print(bcolors.OKGREEN + f'Group Object Created - {obj_name}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError or fireREST.exceptions.ResourceNotFoundError as e:
                    print(bcolors.WARNING + str(e) + bcolors.ENDC)
                    continue
    # ################################## DELETE GROUP NETWORK OBJECTS ##############################################
    if do_func == "del_group_network_objects":
        for obj in data["object-groups"]["object-network-groups"]:
            if 'FMC_INLINE' not in obj:
                try:
                    # Delete network group
                    fmc.object.networkgroup.delete(name=obj)
                    print(bcolors.OKGREEN + f'Group Object Deleted - {obj}' + bcolors.ENDC)
                except fireREST.exceptions.GenericApiError or fireREST.exceptions.ResourceNotFoundError as e:
                    print(bcolors.WARNING + str(e) + bcolors.ENDC)
                    continue
    # ################################## CREATE SECURITY ZONES ##############################################
    if do_func == "create_security_zones":
        for obj in data["security-zones"]:
            zone_data = {'type': 'SecurityZone', 'interfaceMode': 'ROUTED'}
            zone_name = obj['zone']
            zone_data['name'] = zone_name
            try:
                fmc.object.securityzone.create(zone_data)
                print(bcolors.OKGREEN + f"Security Zone Created: {zone_name}" + bcolors.ENDC)
            except Exception as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
    # ################################## DELETE SECURITY ZONES ##############################################
    if do_func == "delete_security_zones":
        for obj in data["security-zones"]:
            zone_name = obj['zone']
            try:
                fmc.object.securityzone.delete(name=zone_name)
                print(bcolors.OKGREEN + f"Security Zone Deleted: {zone_name}" + bcolors.ENDC)
            except Exception as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
    # ################################## CREATE ACCESS CONTROL POLICIES #########################################
    if do_func == "create_access_policy":
        policy_list = []
        for obj in data['access-lists']:
            for el in data['access-lists'][obj]:
                try:
                    policy_name = el['policy_name']
                    policy_list.append(policy_name)
                except Exception as e:
                    # print(e)
                    pass
        policy_set = set(policy_list)
        policy_list_clean = list(policy_set)
        try:
            for policy_name in policy_list_clean:
                acp_data = {'name': policy_name, 'description': 'Access Control Policy',
                            'defaultAction': {'action': 'BLOCK'}}
                fmc.policy.accesspolicy.create(acp_data)
                print(bcolors.OKGREEN + f'Access Control Policy {policy_name} created' + bcolors.ENDC)
        except Exception as e:
            print(bcolors.WARNING + str(e) + bcolors.ENDC)
    # ################################## DELETE ACCESS CONTROL POLICIES #########################################
    if do_func == "delete_access_policy":
        policy_list = []
        for obj in data['access-lists']:
            for el in data['access-lists'][obj]:
                try:
                    policy_name = el['policy_name']
                    policy_list.append(policy_name)
                except Exception as e:
                    # print(e)
                    pass
        policy_set = set(policy_list)
        policy_list_clean = list(policy_set)
        for policy_name in policy_list_clean:
            try:
                fmc.policy.accesspolicy.delete(name=policy_name)
                print(bcolors.OKGREEN + f'Access Control Policy {policy_name} deleted' + bcolors.ENDC)
            except Exception as e:
                print(bcolors.WARNING + str(e) + bcolors.ENDC)
                pass
    # #######################.########### CREATE ACCESS RULES ##############################################
    if do_func == "create_access_rules":
        typical_protocol_list = ['icmp', 'ip', 'tcp', 'udp']
        for obj in data['access-lists']:
            if obj:  # == '268450819':
                obj_list = data['access-lists'][obj]
                policy_obj = {"type": "AccessRule", "enabled": True}  # , "sendEventsToFMC": True, 'logBegin': True}
                logging_present = is_present('logtype', obj_list)
                source_zones_present = is_present('sourceZones', obj_list)
                source_networks_present = is_present('sourceNetworks', obj_list)
                source_ports_present = is_present('sourcePorts', obj_list)
                destination_zones_present = is_present('destinationZones', obj_list)
                destination_networks_present = is_present('destinationNetworks', obj_list)
                destination_ports_present = is_present('destinationPorts', obj_list)
                if source_zones_present:
                    source_zones_list = []
                    source_zones = {"sourceZones": {"objects": source_zones_list}}
                if source_networks_present:
                    source_networks = {"sourceNetworks": {}}
                    source_networks_lit = {"literals": []}
                    source_networks_obj = {"objects": []}
                if source_ports_present:
                    source_ports = {'sourcePorts': {}}
                    source_ports_lit = {'literals': []}
                    source_ports_obj = {'objects': []}
                if destination_zones_present:
                    destination_zones_list = []
                    destination_zones = {"destinationZones": {"objects": destination_zones_list}}
                if destination_networks_present:
                    destination_networks = {"destinationNetworks": {}}
                    destination_networks_lit = {"literals": []}
                    destination_networks_obj = {"objects": []}
                # Destination port object should be created all the time because of protocol object creation specific
                destination_ports = {'destinationPorts': {}}
                destination_ports_lit = {'literals': []}
                destination_ports_obj = {'objects': []}
                if not source_ports_present and not destination_ports_present:
                    source_protocols = {'sourcePorts': {'literals': []}}
                    for el in data['access-lists'][obj]:
                        if 'icmp' in el.values():
                            destination_ports = {'destinationPorts': {'literals': []}}
                            dst_port_is_duplicate = False
                            try:
                                for port in destination_ports['destinationPorts']['literals']:
                                    if port.get('type') == 'ICMPv4PortLiteral':
                                        dst_port_is_duplicate = True
                            except Exception as e:
                                pass
                            if not dst_port_is_duplicate:
                                dst_port_dict = {'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': 'Any'}
                                destination_ports['destinationPorts']['literals'].append(dst_port_dict)
                                policy_obj.update(destination_ports)
                        else:
                            try:
                                src_protocol = el["protocol"]
                                src_protocol_is_duplicate = False
                                try:
                                    for i in source_protocols.get('sourcePorts')['literals']:
                                        if i.get('protocol') == protocol_map[src_protocol]:
                                            src_protocol_is_duplicate = True
                                except Exception as e:
                                    pass
                                if not src_protocol_is_duplicate:
                                    src_protocol_dict = {"type": "PortLiteral", "protocol": protocol_map[src_protocol]}
                                    source_protocols["sourcePorts"]["literals"].append(src_protocol_dict)
                                    policy_obj.update(source_protocols)
                            except Exception:
                                pass
                for el in data['access-lists'][obj]:
                    # ############################# COLLECTION LOGGING ACTION ##################################
                    if logging_present:
                        logging_type = el.get('logtype')
                        logging_flow_dict = {
                            'flow-end': 'logEnd',
                            'flow-start': 'logBegin'
                        }
                        if logging_type:
                            if logging_type == 'both':
                                logging_policy = {"sendEventsToFMC": True, "logBegin": True, "logEnd": True}
                            else:
                                logging_type = logging_type.strip()
                                logging_action = logging_flow_dict[logging_type]
                                logging_policy = {"sendEventsToFMC": True, logging_action: True}
                            policy_obj.update(logging_policy)
                        # ############################# COLLECTING SOURCE PORTS ####################################
                    protocol = el.get("protocol")
                    if protocol and protocol not in typical_protocol_list:
                        if protocol.isdigit():
                            pass
                        else:
                            protocol = protocol.replace('ipinip', 'ipip')
                            protocol = protocol_map[protocol]
                        dst_port_is_duplicate = False
                        destination_ports_exist = destination_ports.get('destinationPorts').get('literals')
                        if destination_ports_exist:
                            for port in destination_ports['destinationPorts']['literals']:
                                if port.get('protocol') == protocol:
                                    dst_port_is_duplicate = True
                        if not dst_port_is_duplicate:
                            dst_port_dict = {'type': 'PortLiteral', 'protocol': protocol}
                            destination_ports_lit['literals'].append(dst_port_dict)
                            destination_ports['destinationPorts'].update(destination_ports_lit)
                    if protocol and protocol == 'icmp':
                        destination_port = el.get("destinationPorts")
                        icmp_type = icmp_type_dict.get(destination_port)
                        if destination_port:
                            dst_port_is_duplicate = False
                            destination_ports_exist = destination_ports.get('destinationPorts').get('literals')
                            if destination_ports_exist:
                                for port in destination_ports['destinationPorts']['literals']:
                                    if port.get('icmpType') == icmp_type:
                                        dst_port_is_duplicate = True
                            if not dst_port_is_duplicate:
                                dst_port_dict = {'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': icmp_type}
                                destination_ports['destinationPorts']['literals'].append(dst_port_dict)
                        else:
                            dst_port_is_duplicate = False
                            dst_ports_present = destination_ports.get('destinationPorts').get('literals')
                            if dst_ports_present:
                                for port in destination_ports['destinationPorts']['literals']:
                                    if port.get('type') == 'ICMPv4PortLiteral':
                                        dst_port_is_duplicate = True
                                if not dst_port_is_duplicate:
                                    dst_port_dict = {'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': 'Any'}
                                    if not destination_ports_present:
                                        destination_ports['destinationPorts']['literals'].append(dst_port_dict)
                                        policy_obj.update(destination_ports)
                                    else:
                                        destination_ports_lit["literals"].append(dst_port_dict)
                                        destination_ports['destinationPorts'].update(destination_ports_lit)
                    if source_ports_present:
                        try:
                            source_port = el["sourcePorts"]
                            if not source_port.isdigit() and not is_range(
                                    source_port) and source_port not in port_map.keys():
                                src_port_is_duplicate = False
                                try:
                                    for port in source_ports.get('sourcePorts')['objects']:
                                        if port.get('name') == source_port:
                                            src_port_is_duplicate = True
                                except Exception as e:
                                    pass
                                if not src_port_is_duplicate:
                                    src_port_dict = {}
                                    port_data = fmc.object.port.get(name=source_port)
                                    src_port_dict["name"] = source_port
                                    src_port_dict["protocol"] = port_data["protocol"]
                                    src_port_dict["id"] = port_data["id"]
                                    src_port_dict["type"] = port_data["type"]
                                    source_ports_obj["objects"].append(src_port_dict)
                                    source_ports['sourcePorts'].update(source_ports_obj)
                                    # policy_obj.update(source_ports)
                                    # print(policy_obj)
                            else:
                                src_port_is_duplicate = False
                                if source_port.isdigit():
                                    pass
                                else:
                                    source_port = port_map[source_port]
                                try:
                                    for port in source_ports.get('sourcePorts')['literals']:
                                        if port.get('port') == source_port:
                                            src_port_is_duplicate = True
                                except Exception as e:
                                    pass
                                if not src_port_is_duplicate:
                                    src_port_dict = {}
                                    src_port_dict["type"] = "PortLiteral"
                                    src_port_dict["protocol"] = protocol_map[el["protocol"]]
                                    src_port_dict["port"] = source_port
                                    source_ports_lit["literals"].append(src_port_dict)
                                    source_ports['sourcePorts'].update(source_ports_lit)
                                    # policy_obj.update(source_ports)
                                    # print(policy_obj)
                        except Exception as e:
                            # print(e)
                            pass
                    # ############################# COLLECTING DESTINATION PORTS ####################################
                    if destination_ports_present:
                        if protocol != 'icmp':
                            try:
                                destination_port = el["destinationPorts"]
                                if not destination_port.isdigit() and not is_range(
                                        destination_port) and destination_port not in port_map.keys():
                                    dst_port_is_duplicate = False
                                    try:
                                        for port in destination_ports.get('destinationPorts')['objects']:
                                            if port.get('name') == destination_port:
                                                dst_port_is_duplicate = True
                                    except Exception as e:
                                        pass
                                    if not dst_port_is_duplicate:
                                        dst_port_dict = {}
                                        port_data = fmc.object.port.get(name=destination_port)
                                        dst_port_dict["name"] = destination_port
                                        dst_port_dict["protocol"] = port_data["protocol"]
                                        dst_port_dict["id"] = port_data["id"]
                                        dst_port_dict["type"] = port_data["type"]
                                        destination_ports_obj["objects"].append(dst_port_dict)
                                        destination_ports['destinationPorts'].update(destination_ports_obj)
                                        # policy_obj.update(destination_ports)
                                        # print(policy_obj)
                                else:
                                    dst_port_is_duplicate = False
                                    if destination_port.isdigit():
                                        pass
                                    else:
                                        destination_port = port_map[destination_port]
                                    try:
                                        for port in destination_ports.get('destinationPorts')['literals']:
                                            if port.get('port') == destination_port:
                                                dst_port_is_duplicate = True
                                    except Exception as e:
                                        pass
                                    if not dst_port_is_duplicate:
                                        dst_port_dict = {}
                                        dst_port_dict["type"] = "PortLiteral"
                                        dst_port_dict["protocol"] = protocol_map[el["protocol"]]
                                        dst_port_dict["port"] = destination_port
                                        destination_ports_lit["literals"].append(dst_port_dict)
                                        destination_ports['destinationPorts'].update(destination_ports_lit)
                                        # policy_obj.update(destination_ports)
                                        # print(policy_obj)
                            except Exception as e:
                                # print(e)
                                pass
                    # ############################ Check for Source Zones ############################
                    if source_zones_present:
                        try:
                            source_zone_name = el['sourceZones']
                            source_zone_is_duplicate = False
                            for zone in source_zones_list:
                                if source_zone_name == zone.get('name'):
                                    source_zone_is_duplicate = True
                            if not source_zone_is_duplicate:
                                source_zone = FMCobject(name=source_zone_name)
                                source_zone_dict = source_zone.get_object_json()
                                source_zones["sourceZones"]["objects"].append(source_zone_dict)
                        except Exception:
                            pass
                    # ############################ Check for Destination Zones ############################
                    if destination_zones_present:
                        try:
                            destination_zone_is_duplicate = False
                            destination_zone_name = el['destinationZones']
                            for zone in destination_zones_list:
                                if destination_zone_name == zone.get('name'):
                                    destination_zone_is_duplicate = True
                            if not destination_zone_is_duplicate:
                                destination_zone = FMCobject(name=destination_zone_name)
                                destination_zone_dict = destination_zone.get_object_json()
                                destination_zones["destinationZones"]["objects"].append(destination_zone_dict)
                        except Exception:
                            pass
                    # ################################# GET ACCESS POLICY NAME #####################################
                    try:
                        acp_name = el['policy_name']
                        print(f'Policy name: {policy_name}')
                    except Exception:
                        pass
                    # ################################# GET RULE NAME ########################################
                    try:
                        rule_name = el['rule_name']
                        print(f'Rule name: {rule_name}')
                        policy_obj.update({'name': rule_name})
                    except Exception:
                        pass
                    # ################################# GET ACL ACTION  ########################################
                    try:
                        rule_action_from_json = el['action']
                        rule_action = rule_action_dict[rule_action_from_json]
                        policy_obj.update({'action': rule_action})
                    except Exception:
                        pass

                    # ################################# COLLECTING SOURCE NETWORKS #####################################
                    if source_networks_present:
                        try:
                            source_net = el["sourceNetworks"]
                            if "FMC_INLINE" in source_net:
                                # print(f'Auto Generated Object Reconstruction Started: {source_net}')
                                source_net_unbox = data["object-groups"]["object-network-groups"][source_net][
                                    'network-objects']
                                try:
                                    src_networks = source_net_unbox['networks']
                                    src_net_is_duplicate = False
                                    for ip in src_networks:
                                        for sl in source_networks_lit['literals']:
                                            if ip == sl.get('value'):
                                                src_net_is_duplicate = True
                                        if not src_net_is_duplicate:
                                            if "/32" in ip:
                                                src_net_data = {'type': 'Host', 'value': ip}
                                            else:
                                                src_net_data = {'type': 'Network', 'value': ip}
                                            source_networks_lit["literals"].append(src_net_data)
                                            source_networks["sourceNetworks"].update(source_networks_lit)
                                    # print(source_networks)
                                except:
                                    pass
                                    # print('No networks')
                                try:
                                    src_objects = source_net_unbox['objects']
                                    for objct in src_objects:
                                        src_obj_is_duplicate = False
                                        for so in source_networks_obj['objects']:
                                            if objct == so.get('name'):
                                                src_obj_is_duplicate = True
                                        if not src_obj_is_duplicate:
                                            try:
                                                src_net_id = fmc.object.host.get(name=objct)['id']
                                                src_net_data = {'type': 'Host', 'name': objct, 'id': src_net_id}
                                            except Exception as exp1:
                                                # print(f'Exception while looking fo host id: {exp1}')
                                                src_net_id = fmc.object.network.get(name=objct)['id']
                                                src_net_data = {'type': 'Network', 'name': objct, 'id': src_net_id}
                                            source_networks_obj["objects"].append(src_net_data)
                                            source_networks["sourceNetworks"].update(source_networks_obj)
                                    # print(source_networks)
                                except:
                                    pass
                                    # print('No objects')
                            else:
                                try:
                                    source_network = ipaddress.ip_network(source_net)
                                    source_network = str(source_network)
                                    src_net_is_duplicate = False
                                    for sl in source_networks_lit['literals']:
                                        if source_network == sl.get('value'):
                                            src_net_is_duplicate = True
                                    if not src_net_is_duplicate:
                                        if "/32" in source_network:
                                            src_net_data = {'type': 'Host', 'value': source_network}
                                        else:
                                            src_net_data = {'type': 'Network', 'value': source_network}
                                        source_networks_lit["literals"].append(src_net_data)
                                        source_networks["sourceNetworks"].update(source_networks_lit)
                                        # print(source_networks)
                                except ValueError:
                                    src_obj_is_duplicate = False
                                    for so in source_networks_obj['objects']:
                                        if source_net == so.get('name'):
                                            src_obj_is_duplicate = True
                                    if not src_obj_is_duplicate and source_net != 'any':
                                        try:
                                            src_net_id = fmc.object.host.get(name=source_net)['id']
                                            src_net_data = {'type': 'Host', 'name': source_net, 'id': src_net_id}
                                        except Exception as exp:
                                            # print(f'Exception while looking fo host id: {exp}')
                                            src_net_id = fmc.object.network.get(name=source_net)['id']
                                            src_net_data = {'type': 'Network', 'name': source_net, 'id': src_net_id}
                                        source_networks_obj["objects"].append(src_net_data)
                                        source_networks["sourceNetworks"].update(source_networks_obj)
                                    # print(source_networks) ### wrong out point
                        except Exception as e:
                            pass
                    if destination_networks_present:
                        try:
                            # ############################# COLLECTING DESTINATION NETWORKS ####################################
                            destination_net = el["destinationNetworks"]
                            if "FMC_INLINE" in destination_net:
                                # print(f'Auto Generated Object Reconstruction Started: {destination_net}')
                                destination_net_unbox = data["object-groups"]["object-network-groups"][destination_net][
                                    'network-objects']
                                try:
                                    dst_networks = destination_net_unbox['networks']
                                    for destination_network in dst_networks:
                                        dst_net_is_duplicate = False
                                        for dl in destination_networks_lit['literals']:
                                            if destination_network == dl.get('value'):
                                                dst_net_is_duplicate = True
                                        if not dst_net_is_duplicate:
                                            if "/32" in destination_network:
                                                src_net_data = {'type': 'Host', 'value': destination_network}
                                            else:
                                                src_net_data = {'type': 'Network', 'value': destination_network}
                                            destination_networks_lit["literals"].append(src_net_data)
                                            destination_networks["destinationNetworks"].update(destination_networks_lit)
                                except:
                                    pass
                                    # print('No networks')
                                try:
                                    dst_objects = destination_net_unbox['objects']
                                    for dst_object in dst_objects:
                                        dst_obj_is_duplicate = False
                                        for do in destination_networks_obj['objects']:
                                            if dst_object == do.get('name'):
                                                dst_obj_is_duplicate = True
                                        if not dst_obj_is_duplicate:
                                            try:
                                                dst_net_id = fmc.object.network.get(name=dst_object)['id']
                                                dst_net_data = {'type': 'Network', 'name': dst_object, 'id': dst_net_id}
                                            except Exception as exp:
                                                # print(f'Exception while looking fo network id: {exp}')
                                                dst_net_id = fmc.object.host.get(name=dst_object)['id']
                                                dst_net_data = {'type': 'Host', 'name': dst_object, 'id': dst_net_id}
                                            destination_networks_obj["objects"].append(dst_net_data)
                                            destination_networks["destinationNetworks"].update(destination_networks_obj)
                                    # print(destination_networks) # wrong out point
                                except:
                                    pass
                                    # print('No objects')
                            else:
                                try:
                                    destination_network = ipaddress.ip_network(destination_net)
                                    destination_network = str(destination_network)
                                    dst_net_is_duplicate = False
                                    for dl in destination_networks_lit['literals']:
                                        if destination_network == dl.get('value'):
                                            dst_net_is_duplicate = True
                                    if not dst_net_is_duplicate:
                                        if "/32" in destination_network:
                                            src_net_data = {'type': 'Host', 'value': destination_network}
                                        else:
                                            src_net_data = {'type': 'Network', 'value': destination_network}
                                        destination_networks_lit["literals"].append(src_net_data)
                                        destination_networks["destinationNetworks"].update(destination_networks_lit)
                                    # print(destination_networks)
                                except Exception as ValueError:
                                    dst_obj_is_duplicate = False
                                    for i in destination_networks_obj['objects']:
                                        if destination_net == i.get('name'):
                                            dst_obj_is_duplicate = True
                                    if not dst_obj_is_duplicate and destination_net != 'any':
                                        try:
                                            dst_net_id = fmc.object.network.get(name=destination_net)['id']
                                            dst_net_data = {'type': 'Network', 'name': destination_net,
                                                            'id': dst_net_id}
                                        except Exception as exp:
                                            # print(f'Exception while looking fo host id: {exp}')
                                            dst_net_id = fmc.object.host.get(name=destination_net)['id']
                                            dst_net_data = {'type': 'Host', 'name': destination_net, 'id': dst_net_id}
                                        destination_networks_obj["objects"].append(dst_net_data)
                                        destination_networks["destinationNetworks"].update(destination_networks_obj)
                        except Exception as exp:
                            # print(exp)
                            pass
                time.sleep(0.2)
                # if len(source_zones['sourceZones']['objects']) != 0:
                if source_ports_present:
                    policy_obj.update(source_ports)
                if destination_ports_present:
                    policy_obj.update(destination_ports)
                if source_zones_present:
                    policy_obj.update(source_zones)
                # if len(destination_zones['destinationZones']['objects']) != 0:
                if destination_zones_present:
                    policy_obj.update(destination_zones)
                # if source_networks['sourceNetworks']:
                if source_networks_present:
                    policy_obj.update(source_networks)
                # if destination_networks['destinationNetworks']:
                if destination_networks_present:
                    policy_obj.update(destination_networks)
                try:
                    fmc.policy.accesspolicy.accessrule.create(data=policy_obj, container_name=acp_name)
                    print(bcolors.OKGREEN + str(policy_obj) + bcolors.ENDC)
                except Exception as exp:
                    print(bcolors.FAIL + str(policy_obj) + bcolors.ENDC)
                    print(bcolors.FAIL + f'-------ERROR------{exp}' + bcolors.ENDC)


class Device:
    def __init__(self, ip_address=None, device_name=None):
        self.ip_address = ip_address
        self.device_name = device_name

    def get_interfaces(self):
        result = fmc.device.devicerecord.subinterface.get(container_name=self.device_name)
        return result

    def get_interfaces_uuid(self, name):
        result = fmc.device.devicerecord.subinterface.get(container_name=self.device_name)
        for i in result:
            if i['ifname'] == name:
                uuid = i['id']
        if uuid:
            return uuid
        else:
            return None

    def delete_interfaces(self, interface=None):
        uuid = self.get_interfaces_uuid(name=interface)
        result = fmc.device.devicerecord.subinterface.delete(container_name=self.device_name, uuid=uuid)
        return result


intf_data = {
    'type': 'SubInterface',
    'subIntfId': 300,
    'name': 'GigabitEthernet0/0'
}

intf_data = {
    'type': 'SubInterface',
    'securityZone': {
        'id': 'e73e5a56-3121-11ee-a343-dfe16236b886',
        'type': 'SecurityZone'
    },
    'vlanId': 300,
    'subIntfId': 300,
    'enabled': True,
    'ipv4': {'static': {'address': '10.3.3.2', 'netmask': '24'}},
    'name': 'GigabitEthernet0/0',
    'id': '00000000-0000-0ed3-0000-025769803907',
    'priority': 0,
    'ifname': 'VLAN300'
}

# fmc.device.devicerecord.subinterface.get(container_name='FTD_for_KVM')
# fmc.device.devicerecord.subinterface.create(container_name='FTD_for_KVM', data=intf_data)
# print('Interface Created')
# device = Device(device_name='FTD_for_KVM')
# interfaces = device.get_interfaces()
# device.delete_interfaces(interface='VLAN300')
# print(interfaces)


if action == "create_all":
    do("create_host_objects")
    do("create_network_objects")
    do("create_group_network_objects")
    do("create_port_objects")
    do("create_security_zones")
    do("create_access_policy")
    do("create_access_rules")
    nat_policy = FMCobject(name='Reconstructed NAT')
    nat_policy.create_nat_policy()
    nat_rules('create_auto_nat', 'Reconstructed NAT', source_data=data)

if action == "delete_all":
    # Delete All
    do("delete_access_policy")
    do("del_port_objects")
    do("del_group_network_objects")
    do("del_host_objects")
    do("del_network_objects")
    do("del_port_objects")
    do("delete_security_zones")
    nat_policy = FMCobject(name='Reconstructed NAT')
    nat_policy.delete_nat_policy()
