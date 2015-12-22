#!/usr/bin/env python27
# Author: RColvin  fl
import ntpath
import hashlib
import os, glob, shutil, sys
import os.path
from os import stat
from pwd import getpwnam
from pwd import getpwuid
from grp import getgrnam
import subprocess
import zipfile
import base64
import struct
import subprocess
import yaml
from yaml import load, dump

import boto.ec2
import boto3

from datetime import datetime, date, timedelta
from dateutil import parser
from pprint import pprint
import time
import traceback
import re
import colorama
from colorama import Fore, Back, Style

colorama.init()


region=''
t_list=None
s_location= ""
AMI=None
key_id=None
ec2In=""
volumeSize=None
mkey=""
sNets=None
sgIDs=None
zoneIn=""
VPCs=None
aws_key=""
aws_secret=""
test_name="TEST-performance"

#TODO: Abstact aws connection types into region based global object

class generic(object):
        def __init__(self, *initial_data, **kwargs):
                for dictionary in initial_data:
                        for key in dictionary:
                                setattr(self,key,dictionary[key])
                        for key in kwargs:
                                setattr(self, key, kwargs[key])

def printColor(a_msg):
    spacer="  "
    for msg in a_msg:
        if ('[E]' in msg):
            print(Fore.RED + msg + Style.RESET_ALL)
        elif '-----' in msg:
            print(Fore.BLACK +Back.WHITE + msg + Style.RESET_ALL)
        elif '_____' in msg:
            print(spacer+Fore.BLACK +Back.CYAN + msg + Style.RESET_ALL)
        elif '.....' in msg:
            print(spacer+spacer+Fore.BLACK +Back.GREEN + msg + Style.RESET_ALL)
        else:
            print (msg)

def writeToFile(pathandfile, inputmessagestr):
    stream = open(pathandfile, 'w')
    stream.write(inputmessagestr)
    stream.close()

def getAWSCredentials():
    pathtoaws = '/home/www-data/.aws/credentials'
    with open(pathtoaws) as f:
        for line in f:
            if "aws_access_key_id" in line:
                awskey = line.replace("aws_access_key_id=", "")
                awskey = awskey.replace("\n", "")
                # print '   aws_access_key_id: %s'%(awskey)
            if "aws_secret_access_key" in line:
                awssecretkey = line.replace("aws_secret_access_key=", "")
                awssecretkey = awssecretkey.replace("\n", "")
                # print '   aws_secret_access_key: %s'%(awssecretkey)

    output = [awskey, awssecretkey]
    return output

## Copies target EC2(region) instance to destination region
## create gateway
## VPN set to 
## volume must be in the same av zone as instance
## /dev/xvda
class Clone2Region():
        def main(self):
            global aws_key,aws_secret
            #import boto3  snap-46959572
            awscredent = getAWSCredentials()
            aws_key=awscredent[0]
            aws_secret=awscredent[1]
            ec2 = boto.ec2.connect_to_region(region,aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
            
            originalSShot=self.getSnapShotByEC2(ec2,ec2In,t_list)
            self.clone2Region(ec2,originalSShot,t_list,aws_key,aws_secret)

            printColor(["----- CLONING COMPLETE ---from:%s to:%s--"%(region,t_list)])

        def destroy(self):
            awscredent = getAWSCredentials()
            aws_key=awscredent[0]
            aws_secret=awscredent[1]

            printColor(["----- DELETING ---from:%s --"%(t_list)])
            for r in t_list:
            	self.destroyInstances(r)
            	self.destroyVPC(r)

        def destroyVPC(self,region):
        	vpc = boto3.client('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        	response = vpc.describe_vpcs()
        	vpcID=""
        	for v in response['Vpcs']:
        		try:
        			for t in v['Tags']:
        				if t['Key'] in 'Name':
        					kname=t['Value']
        					if test_name in kname:
        						found = True
        						break
        		except:
        			printColor([".......[W] VPC no tags.. %s ..creating tags...now"%(v['VpcId'])])
        			continue
        		if found:
        			vpcID=v['VpcId']
        			printColor(['_____Deleting VPC now...this will also delete related subnets.in .%s'%(region)])
        			vpcIN = vpc.Vpc(vpcID)
        			vpcIN.delete()
        			break
        def destroyInstances(self,region):
        	client = boto3.client('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        	response=client.describe_instances()
        	found = False
        	instanceID=""
        	for v in response['Reservations']:
        		for i in v['Instances']:
	        		try:
	        			for t in i['Tags']:
	        				if t['Key'] in 'Name':
	        					kname=t['Value']
	        					if test_name in kname:
	        						found = True
	        						instanceID=i['InstanceId']
	        						break
	        					break
	        			if found:
	        				break
	        		except Exception, e:
	        			printColor(["[E]  no instance found for deletion!!! try a different instance!!"])
        		if found:
        			break
        	if found is True:
        		printColor(['_____Deleting image now..in .%s'%(region)])
        		ec2 = boto3.resource('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		instance = ec2.Instance(instanceID)
        		instance.terminate()

        def copyImage(self,conn,label,description):
        	images=conn.get_all_images(filters={'tag-key':"Name"})
        	#images=conn.get_all_images(filters={'Name':label})
        	
        	for i in images:
        		if (label in i.tags[u'Name']):
        			return i
        	image=conn.copy_image(source_region=region,source_image_id=AMI,name=label,description=description)
        	conn.create_tags([image.image_id],{"Name":label})
        	## get the image using the image id
        	img = conn.get_image(image.image_id)
        	return img
        	
        def clone2Region(self,ec2,originalSS,regions,aws_key,aws_secret):
        	global zoneIn
        	## create new connection
        	label=test_name
        	description="PERFORMANCE-TEST-COPIED"
        	existsS=None
        	if (originalSS==None):
        		printColor(["[E]  no snapshot found!!! try a different instance!!"])
        		return None
        	for r in regions:
        		conn = boto.ec2.connect_to_region(r,aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		vol=None
        		#self.sync_keypairs(conn, key_id,public_key_file):
        		existsS=self.existsSnapShot(conn,label)
        		if (existsS==None):
        			existsS=conn.copy_snapshot(source_region=region,source_snapshot_id=originalSS,description=description)
        			conn.create_tags([existsS],{"Name":label})
        		#ss=conn.get_all_snapshots(filters={'snapshot_id':existsS})
        		ss=conn.get_all_snapshots(snapshot_ids=[existsS])
        		self.statusSnap(ss[0])
        		zoneIn =conn.get_all_zones()[0].name
        		for snap in ss:
        			volumeIn=self.existsVolume(conn,label)
        			if volumeIn==None:
        				vol=conn.create_volume(size=volumeSize,zone=zoneIn,snapshot=snap,volume_type="gp2")
        				conn.create_tags([vol.id],{"Name":label})
        				self.statusVol(vol)
        			else:
        				printColor(["%s already has volume with description %s"%(r,description)])
        		if vol is None:
        			volumes=conn.get_all_volumes(filters={'tag-key':'Name'})
        			for v in volumes:
        				if label in v.tags[u'Name']:
        					vol = v
        					break
        		image= self.copyImage(conn,label,description)
        		self.statusImage(image)
        		self.launchAttachEBS(r,image,ss[0],vol,aws_key,aws_secret)

        def launchAttachEBS(self,region,ami,snapshot,vol,aws_key,aws_secret):
        	#placement={''}

        	printColor(["----- LAUNCH INSTANCES in %s with ami:%s  mkey:%s  subnet:%s -----"%(region,ami.id,mkey.name,sNets[region]['SubnetId'])])
        	client = boto3.client('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)

        	#get subnetID for this test
        	#ec2.describe_subnets(filters={''})
        	response=client.describe_instances()
        	found = False
        	lastins=None
        	for v in response['Reservations']:
        		for i in v['Instances']:
        			if i['State']['Name'] == 'terminated' or "shutting" in i['State']['Name']:
        				continue
	        		try:
	        			for t in i['Tags']:
	        				if t['Key'] in 'Name':
	        					kname=t['Value']
	        					if test_name in kname:
	        						found = True
	        						break
	        					break
	        			if found:
	        				lastins=i
	        				break
	        		except Exception, e:
	        			continue
	        			#print "no instance tag NAME in %s:::%s"%(i['InstanceId'], e)
        		if found:
        			break
        	#raise ValueError(' TESTING in launchAttachEBS')
        	if found is False:
        		printColor(['_____creating image now..in .%s'%(region)])
        		ec2 = boto3.resource('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		Placement={
			        'AvailabilityZone': zoneIn,
			        'Tenancy': 'default'
			    }
        		print "using snapshot for image: %s"%(snapshot.id)


        		#BlockDeviceMappings doesn't seem to work for first time builds in /dev/xvda
        		instances=ec2.create_instances(ImageId=ami.id,SecurityGroupIds=[sgIDs[region]],SubnetId=sNets[region]['SubnetId'],InstanceType='m3.large',MinCount=1,MaxCount=1,KeyName=mkey.name, Placement=Placement)
        		instance=instances[0]
        		#ec2.create_tags(Resources=[instance.id],Tags=[{'Key':'Name','Value':test_name}])
        		self.Tag(ec2,instance.id, 'Name', test_name)
        		self.statusInstnc(client,ec2,instance)
        		self.volumeAttach(client,ec2,instance,vol)
	        else:
        		printColor(['_____image %s found .in .%s Continue.'%(lastins['InstanceId'],region)])
        		ec2 = boto3.resource('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		instance = ec2.Instance(lastins['InstanceId'])
        		self.volumeAttach(client,ec2,instance,vol)

        def volumeAttach(self,client,ec2,ins,vol):
        	printColor(["----- volumeAttach instance state is %s"%(ins.state['Name'])])
        	if 'stop' not in ins.state['Name']:
        		ins.stop()
        		self.statusInstncSTOP(client,ec2,ins)
        	else:
        		print "    instance state is  .......stopped????"

        	#find volume that is currently attached to instance
        	response = client.describe_volumes()
        	for v in response['Volumes']:
        		if len(v['Attachments']) ==0:
        			continue
        		if v['Attachments'][0]['InstanceId'] == ins.id:
        				evol = client.detach_volume(VolumeId=v['VolumeId'],InstanceId=ins.id,Device='/dev/xvda')
        				printColor(['_____Detaching Volume id:%s..%s'%(v['VolumeId'],v['State'])])
        				vold = ec2.Volume(v['VolumeId'])
        				while vold.state == 'attached':
        					time.sleep(3)
        					printColor(['_____2 Detaching Volume..%s'%(vold.status)])
        					vold = ec2.Volume(v['VolumeId'])
        				break
        	time.sleep(8)
        	dvol=client.attach_volume(VolumeId=vol.id,InstanceId=ins.id,Device='/dev/xvda')
        	printColor(['------- Attach Volume id:%s..%s -----'%(vol.id,ins.id)])
        	vol = ec2.Volume(vol.id)
        	while vol.state != 'attached' and vol.state != 'in-use' :
        		time.sleep(3)
        		printColor(['_____Attaching Volume..%s'%(vol.state)])
        		vol = ec2.Volume(vol.id)

        	ins.start()
        	self.statusInstnc(client,ec2,ins)
        	self.associateIP(client,ec2,ins)

       
        def associateIP(self,client,ec2,ins):
        	gtws = client.describe_internet_gateways()
        	found = False
        	print gtws
        	igw=None
        	for g in gtws['InternetGateways']:
        		try:
        			for t in g['Attachments']:
        				if t['VpcId'] ==ins.vpc_id:
    						found =True
    						print ""%(t['State'])
    						igw = g
    						break
        			if found is True:
        				break
        		except:
        			continue
        	if found == False:
        		printColor(['------- Creating Gateway None Found'])
        		igw = ec2.create_internet_gateway()
        		self.Tag(client,igw.id, 'Name', test_name)
        		igw.attach_to_vpc(VpcId=ins.vpc_id)

        	response=client.describe_addresses()
        	print response
        	found = False
        	for ip in response['Addresses']:
        		if 'vpc' in ip['Domain']:
        			try:
        				if ins.id==ip['InstanceId']:
        					found=True
        					break
        			except:
        				continue
        	if found== False:
	        	eip=client.allocate_address(Domain='vpc')
	        	client.associate_address(InstanceId=ins.id,AllocationId=eip['AllocationId'])
	        	printColor(['_____Attaching ELASTIC IP %s  to..%s'%(eip['PublicIp'],ins.id)])
        	

        def statusInstncSTOP(self,client,ec2,ins):
        	newins = ec2.Instance(ins.id)
        	while 'stopped' not in newins.state['Name']:
        		newins = ec2.Instance(newins.id)
        		printColor(['_____Instance stop..%s'%(newins.state['Name'])])
        		time.sleep(10)
        	return newins.state['Name']

        def statusInstnc(self,client,ec2,ins):
        	newins = ec2.Instance(ins.id)
        	printColor(['_____Instance start..%s'%(newins.state['Name'])])
        	if 'run' not in newins.state['Name']:
        		time.sleep(10)
        		self.statusInstnc(client,ec2,newins)


        def statusVol(self,vol):
        	while vol.status != 'available':
        		time.sleep(10)
        		printColor(['_____Volume..%s'%(vol.status)])
        		vol.update()
        def statusSnap(self,ss):
        	while ss.status != 'completed':
        		time.sleep(10)
        		printColor(['_____snapshot..%s'%(ss.status)])
        		ss.update()
        def statusImage(self,img):
        	while img.state != 'available':
        		time.sleep(10)
        		printColor(['_____Image..%s'%(img.state)])
        		img.update()
        def existsVolume(self,ec2,label):
        	volumes = ec2.get_all_volumes(filters={'tag:Name':label})
        	for v in volumes:
        		if (label in v.tags[u'Name']):
        			return v
        	return None
        def existsSnapShot(self,ec2,label):
        	snapshots = ec2.get_all_snapshots(filters={'tag:Name':label})
        	if len(snapshots)>0:
        		return snapshots[0].id
        	return None

        def getSnapShotByEC2(self,ec2,instance_name,regions):
        	global AMI, key_id, sNets,VPCs
        	printColor(["----- GET SNAPSHOT for %s -----"%(instance_name)])
        	volumes = ec2.get_all_volumes(filters={'attachment.instance-id':instance_name})
        	reservations = ec2.get_all_instances(filters={'instance-id':instance_name})
        	if len(reservations)>0:
        		AMI = reservations[0].instances[0].image_id
        		groups =reservations[0].instances[0].groups
        		sNets,VPCs=self.copySecurityAppliance(ec2,groups,regions)
        		key_id=reservations[0].instances[0].key_name
        		self.copyKeys(ec2,key_id,regions)
        	snapshots = volumes[0].snapshots()
        	if len(snapshots)==0:
        		print "[E] NO SNAPSHOTS FOUND PLEASE CREATE ONE, THAT IS ASSIGNED TO VOLUME(%s), BEFORE CONTINUING",volumes[0]
        	snap_sorted = sorted([(s.id, s.start_time) for s in snapshots], key=lambda k: k[1])
        	for s in snap_sorted:
        		return s[0]
        	return None

        def copySecurityAppliance(self,ec2,groups,regions):
        	sgroups=ec2.get_all_security_groups()
        	vpcIn=None
        	local_sg=[]
        	for g in groups:
        		for s in sgroups:
        			if g.name in s.name:
        				print s.name
        				local_sg.append(s)
        				vpcIn=s.vpc_id
        				break;
        	vpcs = self.cloneVPC(aws_key, aws_secret, regions, vpcIn)
        	self.cloneSecurityGroup(aws_key, aws_secret, regions, local_sg, vpcs)
        	subnets=self.cloneSubNet(aws_key, aws_secret, regions, local_sg, vpcs)
        	
        	printColor(["----- COPY VPCs/suBnets -----"])
        	printColor(["____Subnets:%s"%(subnets)])
        	printColor(["____VPCs:%s"%(vpcs)])
        	#print subnets
        	return (subnets,vpcs)

        def getRouteTable(self,ec2,vpcID):
        	rtbls = ec2.describe_route_tables(Filters=[ { 'Name': 'vpc-id', 'Values': [ vpcID ] } ] )
        	default_rtb = None
        	for table in rtbls['RouteTables']:
        		if table['Associations'] and 'Main' in table['Associations'][0]:
        			default_rtb = table['RouteTableId']
        	return default_rtb
        #Clone subnets and then add to routetable accordingly
        def cloneSubNet(self,aws_key,aws_secret,regions,local_s,vpcs):
        	subnets={}
        	for r in regions:
        		vpc = vpcs[r]
        		client = boto3.client('ec2', r, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		allsnets = client.describe_subnets()
        		found=False
        		for sn in allsnets['Subnets']:
        			try:
	        			for t in sn['Tags']:
	        				if t['Key'] in 'Name':
	        					if test_name in t['Value']:
	        						found =True
	        						break
	        			if found is True:
	        				break
	        		except:
	        			continue
	        	if found is True:
	        		subnets[r] =sn
	        		continue
        		try:
        			snet=client.create_subnet(CidrBlock='10.0.1.0/24', VpcId=vpc['VpcId'])
        			sID = snet['Subnet']['SubnetId']
        			#client.create_tags(Resources=[sID],Tags=[{'Key':'Name','Value':test_name}])
        			self.Tag(client,sID, 'Name', test_name)
        			subnets[r]=snet['Subnet']
        			default_rtb = self.getRouteTable(client,vpc['VpcId'])
        			ec2_client.associate_route_table( SubnetId=sID,RouteTableId=default_rtb )
        		except Exception, e:
        			printColor([".......[W] subnet creation warning...possibly already exists %s"%(e)])
        	return subnets



        def cloneSecurityGroup(self,aws_key,aws_secret,regions,local_s,vpcs):
        	global test_name,sgIDs
        	sgIDs={}
        	for r in regions:
        		client = boto3.client('ec2', r, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		#conn = boto.ec2.connect_to_region(r,aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		#rgroups = ec2.get_all_security_groups()
        		rgroups=client.describe_security_groups()
        		#print rgroups
        		## Attempting to get the complete security objects from given EC2 reference
        		for s in local_s:
        			found=False
        			for rg in rgroups['SecurityGroups']:
        				try:
	        				for t in rg['Tags']:
	        					if t['Key'] in 'Name':
	        						kname=t['Value']
	        						if test_name in kname:
	        							found=True
	        							sgIDs[r]=rg['GroupId']
	        							break
	        			except:
	        				continue

        				if s.name in rg['GroupName']:
        					found=True
        				if found==True:
        					break
        			if found is False :
        				scg = client.create_security_group(GroupName=test_name,Description=test_name,VpcId=vpcs[r]['VpcId'])
        				#client.create_tags(Resources=[scg['GroupId']],Tags=[{'Key':'Name','Value':test_name}])
        				self.Tag(client,scg['GroupId'], 'Name', test_name)
        				client.authorize_security_group_ingress(GroupId=scg['GroupId'], IpProtocol='tcp',CidrIp='0.0.0.0/0',ToPort=22,FromPort=22 )
        				client.authorize_security_group_ingress(GroupId=scg['GroupId'], IpProtocol='tcp',CidrIp='0.0.0.0/0',ToPort=80,FromPort=80 )
        				sgIDs[r]=scg['GroupId']
        				break

        def cloneVPC(self,aws_key,aws_secret,regions,vpcIn):
        	global test_name
        	vpc = boto3.client('ec2', region, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        	response = vpc.describe_vpcs(VpcIds=[vpcIn])
        	kname = ''
        	regionalVPC={}
        	vpc_source=None
        	for v in response['Vpcs']:
        		vpc_source=v
        		try:
        			block=v['CidrBlock']
        			for t in v['Tags']:
        				if t['Key'] in 'Name':
        					kname=t['Value']
        		except:
        			printColor([".......[W] VPC no tags.. %s ..creating tags...now"%(v['VpcId'])])
        	if kname=='':
        		kname = "%s-source"%(test_name)
        		#vpc.create_tags(Resources=[vpcIn],Tags=[{'Key':'Name','Value':kname}])
        		self.Tag(vpc,vpcIn, 'Name', test_name)
        	test_name = "%s-%s"%(test_name,kname)
        	kname=test_name

        	for r in regions:
        		vpcR = boto3.client('ec2', r, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        		all_vpcs = vpcR.describe_vpcs()
        		found=False
        		for v in all_vpcs['Vpcs']:
        			try:
        				for t in v['Tags']:
        					if t['Key'] in 'Name':
        						if t['Value'] in kname:
        							regionalVPC[r]=v
        							found = True
        							break
        			except:
        				printColor([".......[W] NOT found %s in other region %s "%(kname,r)])
        		if found is False:
        			newVpc=vpcR.create_vpc(CidrBlock=block,InstanceTenancy='default')
        			vpcID=newVpc['Vpc']['VpcId']
        			#vpcR.create_tags(Resources=[vpcID],Tags=[{'Key':'Name','Value':test_name}])
        			self.Tag(vpcR,vpcID, 'Name', test_name)
        			vpcR.modify_vpc_attribute(VpcId=vpcID,EnableDnsHostnames={ 'Value': True } )
        			printColor([".......VPC created %s[%s] with DNS Enabled in  %s "%(kname,vpcID,r)])
        			regionalVPC[r]=newVpc['Vpc']
     
        	return regionalVPC        

        def Tag(self,ec2_client,resource, key, value):
        	sleep(4)
        	response = ec2_client.create_tags(Resources = [resource], Tags = [ { 'Key'  : key, 'Value': value, } ] )

        def copyKeys(self,ec2,key_id,regions):
        	global mkey
        	key=ec2.get_all_key_pairs(keynames=[key_id])[0]
        	printColor(["----- COPY KEYS for %s -----"%(key_id)])
        	mkey=key
        	for r in regions:
        		oRegion = boto.ec2.get_region(r)
        		try:
        			mkey=key.copy_to_region(oRegion)
        		except boto.exception.EC2ResponseError,e:
        			if ("Duplicate" in e):
        				continue
        	#print mkey.name
        	#raise ValueError(' TESTING in CopyKeys')
        #def copyVPC(self,ec2,key_id,regions):
        #	for r in regions:



prompt = sys.argv[1]

if 'help' in prompt:
        print "used to copy given snapshot to given dest regions '_' snapshot and original volume size"
        print "subsequently build test server and attach volume"
        print "finally run stack from given source"
        print "python27 PAVERC.py dest-region_ec2instance_size,targetR1_targetR2_targetR3,saltlocation"
        print "--example:"
        print "python27 PAVERC.py us-west-2_i-0b68f4cf_50,us-east-1_us-west-1"
        print "--example: Destroy"
        print "python27 PAVERC.py destroy,us-east-1_us-west-1"

        ## 'ap-southeast-2'  'us-west-1'
else:
        values = prompt.split(',')
        tserver = Clone2Region()
        targets = str(values[1])
        t_list = targets.split("_")
        #s_location= str(values[2])
        if "destroy" in prompt:
        	tserver.destroy()
        else:
        	dest = str(values[0]).split("_")  #//  'zip'  'restore'
        	#try:
        	region=dest[0]
        	ec2In=dest[1]
        	volumeSize=dest[2]
        	if len(region)<7:
        		region = 'us-west-2'
        	elif ' ' in region:
        		region= 'us-west-2'
        	print region
        	#get optional variables
        	tserver.main()
		    #    except Exception, e:
		    #        print "[E] check regions or saltlocation for issue! -->%s", e
	      #  except Exception,e:
	       # 	print "[E] check destination info! ->%s",e
