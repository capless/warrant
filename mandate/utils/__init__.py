import ast


def cognito_to_dict(attr_list, attr_map=None):
    if attr_map is None:
        attr_map = {}
    attr_dict = dict()
    for a in attr_list:
        name = a.get('Name')
        value = a.get('Value')
        if value in ['true', 'false']:
            value = ast.literal_eval(value.capitalize())
        name = attr_map.get(name, name)
        attr_dict[name] = value
    return attr_dict


def dict_to_cognito(attributes, attr_map=None):
    """
    :param attributes: Dictionary of User Pool attribute names/values
    :return: list of User Pool attribute formatted dicts:
    {'Name': <attr_name>, 'Value': <attr_value>}
    """
    if attr_map is None:
        attr_map = {}
    for k, v in attr_map.items():
        if v in attributes.keys():
            attributes[k] = attributes.pop(v)

    return [{'Name': key, 'Value': value} for key, value in attributes.items()]
