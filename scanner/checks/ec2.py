def check_ec2_public_address(instance,instance_name):
    public_ip = instance.get("PublicIp")
    if public_ip:
        return [{
            "rule_id": "EC2-001",
            "severity": "Medium",
            "title": "EC2 instance has an public IP ",
            "resource": instance_name
        }]

    return []

def check_ec2_metadata_service(instance,instance_name):
    metadata_option = instance.get("MetadataOptions",[])
    if metadata_option.get("HttpTokens") == "optional":
        return [{
            "rule_id": "EC2-002",
            "severity": "Medium",
            "title": "EC2 instance allows usage of IMDSv1",
            "resource": instance_name
        }]

    return []

def check_ec2_ebs_encryption(instance,instance_name,ec2_volumes):
    for devices in instance["BlockDeviceMappings"]:
        if devices.get("Ebs"):
            ebs = devices.get("Ebs")
            volume_id = ebs.get("VolumeId")
            for volume in ec2_volumes["Volumes"]:
                if volume_id == volume["VolumeId"]:
                    if not volume["Encrypted"]:
                        return [{
                            "rule_id": "EC2-003",
                            "severity": "Medium",
                            "title": "EC2 instance EBS volume has no encryption",
                            "resource": instance_name
                        }]


    return []

def check_ec2_termination_protection(instance_name,instance_attribute):
    if not instance_attribute["DisableApiTermination"]["Value"]:
        return [{
            "rule_id": "EC2-004",
            "severity": "Medium",
            "title": "EC2 instance does not have termination protection",
            "resource": instance_name
        }]


    return []

