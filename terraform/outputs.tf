output "vpc_id" {
value = aws_vpc.main.id
}

output "public_subnet_id" {
value = aws_subnet.public_subnet.id
}

output "private_subnet_id"{
value = aws_subnet.private_subnet.id
}

output "public_security_group_id"{
value = aws_security_group.public_sg.id
}

output "private_security_group_id"{
value = aws_security_group.private_sg.id
}

output "public_instance_id"{
value = aws_instance.ec2_public.id
}

output "private_instance_id" {
value = aws_instance.ec2_private.id
}