# PAVERC__Python-AWS-VPC-EC2-Region-Cloner
requires:   
- python 2.7
- boto
- boto 3        
Script will Clone most properties from an EC2 instance in one region to N other region(s)
python27 paverc.py dest-region_ec2instance_size,targetR1_targetR2_targetR3,saltlocation  
**example:**   
  ````python27 paverc.py us-west-2_i-0b68f4cf_50,us-east-1_us-west-1  ````     
**example:**   
  ````python27 paverc.py destroy,us-east-1_us-west-1 ````
