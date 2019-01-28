from django.shortcuts import render ,redirect
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
import requests
import pprint
import json
from .forms import ScanAttributes,ProfileAttributes
import uuid
from .models import *
from log.models import *
#from local_settings import API_KEY
from django.conf import settings
from django.http import JsonResponse
from ansi2html_ import ansi2html
import ast
from wsgiref.util import FileWrapper
from django.http import HttpResponse
import os
import uuid
from django.db.models import Q
from django.contrib.auth.decorators import login_required
# Create your views here.






class Custom:
	def get_api_address(self):
		return "http://127.0.0.1:8888"

	def generate_uuid(self):
		return uuid.uuid1()

	def getProjects(self,request):
			content_status=Custom().getApiContent('',"/projects/",{"paused":False})
			if content_status["status"]=="success":
				user_obj=Profile.objects.get(user_id=request.user.id)
				if user_obj.user_role and user_obj.user_role =='admin':
					#print "If cond is true"
					return content_status["data"]
		
				project_list=[]
				for project in content_status["data"]:
					project_list.append(project["id"])
				filtered_scans=Custom().filtered_scans(user_obj,project_list)
				final_list=[]
				for project in content_status["data"]:
					#print "Project id is : "+str(project["id"])
					if str(project["id"]) in list(filtered_scans):
						#print "Matched :"
						final_list.append(project)
				return final_list
			else:
				return -1

	def getOwnership(self,project_id,user_obj):
		try:
			if user_obj.user_role and user_obj.user_role=='admin':
				#print "Current User is admin :"
				return True
		
			project_obj=Projects.objects.get(user=user_obj,project_id=str(project_id))
			#print "Obtained Project obj is :"+str(project_obj)
			#print "User not admin" +str(project_obj)
			if project_obj and project_obj !=None:
				return True
			else:
				return False
		except Exception ,ex:
			#print "Exception caught :"+str(ex)
			return False

	
	def getOwnershipProfile(self,profile_id,user_obj):
		try:
			print "!!!!"
			if str(profile_id) in ["1","2","3","4","5"]:
				return True
				#print "Current User is admin :"
			#	return True
			#print "here i am"+str(profile_id)+str(user_obj)
			profile_id=str(profile_id)
			project_obj=Profiles.objects.get(Q(profile_catagory="Shared") | Q(user=user_obj),Q(profile_id=profile_id))

			if project_obj and project_obj !=None:
				return True
			else:
				return False
		except Exception ,ex:
			print "Exception caught :"+str(ex)
			return False
	
	def filtered_scans(self,user_obj,project_list=[]):
			filtered_list=Projects.objects.values_list('project_id',flat=True).filter(user=user_obj,project_id__in=project_list)
			#print "Else condition is true"
			#print "Filtered list is :"+str(filtered_list)
			return filtered_list
			

	def format_data(self,exploit_data):
		try:
			html=[]
			html.append("<div>")
			return_val=''
			if(isinstance(exploit_data,basestring)):
					exploit_data=json.loads(exploit_data)
					#host_counter=host_counter+1
					if exploit_data:
						entries=exploit_data.get("Entries")
						if(entries):
							for k,v in entries.iteritems():
								if(v):
									command_id=str(k)
									html.append("<b><font color=green><span class='glyphicon glyphicon-info-sign'></span>&nbsp;Command Id : "+str(command_id)+"</font></b><br><br>")
									commands = v[1] if v[1] else "No commands "								
									result=v[2] if v[2] else "No Results "
									final_commands=[]
									if(commands !="No commands"):
										cmd = ast.literal_eval(commands)
										if (isinstance(cmd,list)):
											for c in cmd:
												final_commands.append(c)
												
										else:
											final_commands.append(str(cmd))
									commands=''.join(final_commands)
									#all_exploits=all_exploits+1
									
									html.append("<div style=background-color:black;color:white>Command :<br>"+str(commands).replace("<","&lt").replace(">","&gt").replace('\n','<br>').replace('\r','<br>').replace('\r\n','').replace('\r\r','<br>')+"</div><br>")
									html.append("<div style=background-color:black;color:white>Results : <br>"+str(result.replace("<","&lt").replace(">","&gt")).replace('\n','<br>').replace('\r','<br>').replace('\r\n','').replace('\r\r','<br>') +"</div><br>")
									
				
			html.append('</div>')
			html_final=ansi2html(str(''.join(html)))
			return html_final
				
		except Exception,ee:
			print "Exception caught "+str(ee)
			return -1
		
	def getApiContent(self,project_id,api_extention,add_params=None,request_type="get",files=None,resp_type="plain"):
		api_url=self.get_api_address()
		api_url=api_url+api_extention
		api_key=getattr(settings,'API_KEY',None)
		app_id=getattr(settings,'APP_ID',None)				
		data = {"app_key" : api_key,"project_id":project_id}
		if add_params !=None:
			#print "Recieved add params are :"+str(add_params)
			data.update(add_params)
		if files==None:
			data_json = json.dumps(data)

		#print "Transformmed data to be sent :"+str(data_json)
		
		headers = {'Content-type': 'application/json'}
		if files==None:
			if request_type=="get":
				response = requests.get(api_url, data=data_json, headers=headers)
			else:
				response = requests.post(api_url, data=data_json, headers=headers)
				#print str(response)
				#print str(response.headers['content-type'])
				#print str(response.content)
			#print "Response obtained is :"+str(response)	
		else:
				#print "11"
				response = requests.post(api_url, data=data, files=files)
				#print "22"
		resp={}
		if resp_type=="plain":
			resp=json.loads(str(response.json()))
			return resp 
		else:
			if response.status_code ==200:
				return response.content	
			else:
				return -1
		
		#print "Updated Json format of response is : "+str(resp)	
		
	

	def renderAppropriateTemplate(self,request,proj_id,success_template,error_template,api_uri,api_params):
		print "Hello"
		


class Polling_Scanning(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "\n\n\n\n\nPosted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			#print "\n\n\n\n\n\n\n\nObtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="complete" and (vul_scan_status=="processing" or vul_scan_status=="complete") :
							#print "22"
							content_status=Custom().getApiContent(proj_id,"/polling_scanning/",{"record_list":data,"project_id":proj_id},"post")
							#print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nObtained Response is :"+str(content_status)
							if content_status["status"]=="success":
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								#print "44"
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			#print "Error msg is --->:"+error_msg
			return JsonResponse({'project_id':proj_id,'project_status':'error','success':'False','error':'True','error_msg':error_msg})

		except Exception ,eex:
			try:
				print "99-Indide exception"+str(eex)
				return JsonResponse({'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				#print "101"
				return JsonResponse({'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

	def get(self,request):
		try:
			#print "Posted"
			proj_id=request.GET["proj_id"];
			error_msg=''
			in_prog="In Progress"
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if vul_scan_status=="processing" or vul_scan_status=="complete":
							percentage_status=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'scan'})

							if percentage_status["status"]=="success":
								percentage=int(float(percentage_status["value"]))
								#print "Obtained percentage is ## :"+str(percentage)
								#url_="details_update
								if percentage ==100 or vul_scan_status=="complete":
									percentage=100
									in_prog='complete'
								
								content_status=Custom().getApiContent(proj_id,"/polling_scanning/")
								if content_status["status"]=="success":
										content=content_status["data"]
										#print "\n\n\n\n\n I am here boss \n\n\n\n\n"
										config_=Custom().getApiContent(proj_id,"/config_conc/")
										#print "\n\n\n\n"+"Obtained Config "+"\n\n"+str(config_["data"])
										#print "\n\n\nI have obtained config !!!\n\n"
										if (config_["status"]=="success"):
											content_list=[]
											for c in content:
												#print "Content id is :"+str(c["id"])
												#print "command is"
												#print str(c["Commands"])

												formatted_data=Custom().format_data(c["Commands"])
												if formatted_data == -1:
														formatted_data="No data can be fetched !!"
												#print "reached here "+str(c["id"])
												content_list.append({"id":c["id"],"Commands":formatted_data})
											return render(request,"vul_scan_update.html",{'project_id':proj_id,'percentage':percentage,'content':config_["data"],'updated_content':content_list,'continue':'True','change_contentt':'True','record_list':content_status["record_list"],'project_status':in_prog})
										else:
											#print "OOPS failure "
											error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])

								elif content_status["status"]=="empty":
										return render(request,"vul_scan_update.html",{'project_id':proj_id,'percentage':percentage,'content':'','continue':'True','change_contentt':'False','project_status':in_prog})
								else:
										error_msg='Some failure occured while fetching vul scan results --> '+str(content_status["value"])
								
					
									
							else:
								error_msg='Can not fetch Percentage for current Project '+str(percentage_status["value"])
								
						else:
							#print "Here i am "
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'
		
			#print "Returning"
			print "Returninhg error :"+error_msg
			return render(request,"vul_scan_update.html",{'project_id':proj_id,'project_status':'error','error':'True','change_contentt':"True",'error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99-----"+str(eex)
				return render(request,"vul_scan_update.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101"
				return render(request,"vul_scan_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','change_content':"True",'error_msg':"No project Found--"+str(ex)})


class ScanProfiles():

	def getOne(self,id_):
		profile_list=[]

		content_status=Custom().getApiContent('',"/ScanProfile/",{'profile_id':id_})
		#print str(content_status)
		if content_status["status"]=="success":
			return content_status
		else:
			return -1 

	
	def getAll(self,user=None):
		profile_list=[]
		try:
			if user !=None:
				user_obj=user
				print "User here is : "+str(user_obj)
				profile_ids=list(Profiles.objects.values_list('profile_id',flat=True).filter(user=user_obj).exclude(profile_id='').distinct())
				#print "Obtained Profile id's : "+str(profile_ids)
				if profile_ids != None :
					#print "here@@@"
					content_status=Custom().getApiContent('',"/ScanProfiles/",{'profile_ids':profile_ids})
					#print str(content_status)
				else:
					content_status=Custom().getApiContent('',"/ScanProfiles/",{'profile_ids':"0"})
			else:
				content_status=Custom().getApiContent('',"/ScanProfiles/",{'profile_ids':"0"})
		except Exception ,ex:
				print "Exception : " +str(ex)
				content_status=Custom().getApiContent('',"/ScanProfiles/",{'profile_ids':"0"})

		if content_status["status"]=="success":
			return content_status
		else:
			return -1 

	def Map(self,profile_json,mapper_json):
		mapped={}
		#print "IN mapper"
		try:
			for k,v in profile_json.iteritems():
					#
					if v["Custom"]==False:
						mapped[k]={}
						for tc in v["Test_cases"]:
							#mandatory_mapped[k]["Test_case"]=tc#mapper_json.get(tc,'No Test case Found')
							mapped[k][tc]=mapper_json.get(tc,"No Test Case found")
		except Exception ,exc:
				print "IN exception Mapper : "+str(exc)		
		return mapped

class Polling_Scanning_intermediate(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "\n\n\n\n\nPosted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			#print "\n\n\n\n\n\n\n\nObtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						if discovery_status=="complete" and (vul_scan_status=="paused") and (mode =="sequential" or mode =="sequential_default") :
							#print "22"
							content_status=Custom().getApiContent(proj_id,"/polling_scanning/",{"record_list":data,"project_id":proj_id},"post")
							#print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nObtained Response is :"+str(content_status)
							if content_status["status"]=="success":
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								#print "44"
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			#print "Error msg is --->:"+error_msg
			return JsonResponse({'project_id':proj_id,'project_status':'error','success':'False','error':'True','error_msg':error_msg})

		except Exception ,eex:
			try:
				print "99-Indide exception"+str(eex)
				return JsonResponse({'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				#print "101"
				return JsonResponse({'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

	def get(self,request):
		try:
			#print "Posted"
			proj_id=request.GET["proj_id"];
			error_msg=''
			in_prog="paused"
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						if vul_scan_status=="paused" and discovery_status =="complete" and (mode =="sequential" or mode=="sequential_default"):
							percentage_status=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'scan'})

							if percentage_status["status"]=="success":
								percentage=int(float(percentage_status["value"]))
								if percentage ==100 or vul_scan_status=="complete":
									percentage=100
									in_prog='complete'
								
								content_status=Custom().getApiContent(proj_id,"/polling_scanning/")
								if content_status["status"]=="success":
										content=content_status["data"]
										config_=Custom().getApiContent(proj_id,"/config_conc/")
										if (config_["status"]=="success"):
											content_list=[]
											for c in content:
												formatted_data=Custom().format_data(c["Commands"])
												if formatted_data == -1:
														formatted_data="No data can be fetched !!"
												#print "reached here "+str(c["id"])
												content_list.append({"id":c["id"],"Commands":formatted_data})
											return render(request,"intermediate_update.html",{'project_id':proj_id,'percentage':percentage,'content':config_["data"],'updated_content':content_list,'continue':'True','change_contentt':'True','record_list':content_status["record_list"],'project_status':in_prog})
										else:
											#print "OOPS failure "
											error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])

								elif content_status["status"]=="empty":
										return render(request,"vul_scan_update.html",{'project_id':proj_id,'percentage':percentage,'content':'','continue':'True','change_contentt':'False','project_status':in_prog})
								else:
										error_msg='Some failure occured while fetching vul scan results --> '+str(content_status["value"])
								
					
									
							else:
								error_msg='Can not fetch Percentage for current Project '+str(percentage_status["value"])
								
						else:
							#print "Here i am "
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'
		
			#print "Returning"
			print "Returninhg error :"+error_msg
			return render(request,"intermediate_update.html",{'project_id':proj_id,'project_status':'error','error':'True','change_contentt':"True",'error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99-----"+str(eex)
				return render(request,"vul_scan_update.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101"
				return render(request,"vul_scan_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','change_content':"True",'error_msg':"No project Found--"+str(ex)})

class Scans(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'
	
	

	def get(self,request):
		try:
			paused=request.GET["paused"]
			#print "Value of paused is : "+str(paused)
			if paused == 'True':
				p=True
			else:
				p=False
			#print "value of P is : "+str(p)
			content_status=Custom().getApiContent('',"/projects/",{"paused":p})
			if content_status["status"]=="success":
				user_obj=Profile.objects.get(user_id=request.user.id)
				print "Obtained user role is :" +str(user_obj.user_role) +(user_obj.user.username)
				if user_obj.user_role and user_obj.user_role =='admin':
					#print "If cond is true"
					"""for project in content_status["data"]:
						print "id is :"+str(project["id"])
						try:
							project_obj=Projects.objects.get(project_id=str(project["id"]))
							usr=User.objects.get(id=project_obj.user.user_id)
							project["owner_id"]=usr.first_name
						except Exception ,eee:
							xx=1#pass
							#print str(eee)
						#print project_obj.user_id"""
					return render(request,"scans.html",{'data':content_status["data"],'error':'False','success':'True'})
				print "Here"
				project_list=[]
				for project in content_status["data"]:
					project_list.append(project["id"])
				filtered_scans=Custom().filtered_scans(user_obj,project_list)
				final_list=[]
				for project in content_status["data"]:
					#print "Project id is : "+str(project["id"])
					if str(project["id"]) in list(filtered_scans):
						#print "Matched :"
						#project["owner_id"]=str(user.first_name)
						final_list.append(project)
						#print "appended"
				return render(request,"scans.html",{'data':final_list,'error':'False','success':'True'})
			else:
				return render(request,"scans.html",{'error_msg':content_status["value"],'error':'True','success':'False'})			
			
		except Exception ,eex:
			return render(request,"scans.html",{'error_msg':str(eex),'error':'True','success':'False'})



class Faq(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			with open ("services.txt","r+") as fread:
				my_lines=fread.readlines();	
			
			with open ("video.txt","r+") as fread:
				video_url=fread.read();	

			return render(request,"faq.html",{'faq':my_lines,'video_url':video_url,'error':'False','success':'True'})

		except Exception ,ex:
			print str(ex)
			return render(request,"faq.html",{'error':'True','success':'False','error_msg':str(ex)})
			
class View_intermediate(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			#print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.GET["project_id"];
			proj_name=request.GET["project_name"];
			error_msg=''
			restore_discovery=False
			restore_scanning=False
			restore_both=False
			restore_conf=False
			
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				#print "reached@@@"
				if Custom().getOwnership(proj_id,user_obj):
					#print "About to request for Proj id :"+str(proj_id)
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						add_params={}
						response_url=''
						if (discovery_status=="complete" and vul_scan_status=="paused") and (mode=="sequential" or mode=="sequential_default"):
							restore_discovery=True
							response_url="intermediate.html"
							content_list=[]							
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",None,"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','skip':'true'}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							
						
						if restore_discovery :
								return render(request,response_url,add_params)
								
						else:
							error_msg='Can not Restore the current project with its current status -- Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'

			return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99"
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(eex)})
			except Exception ,ex:
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(ex)})

class Restore_State(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			#print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.GET["project_id"];
			proj_name=request.GET["project_name"];
			error_msg=''
			restore_discovery=False
			restore_scanning=False
			restore_both=False
			restore_conf=False
			
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				#print "reached@@@"
				if Custom().getOwnership(proj_id,user_obj):
					#print "About to request for Proj id :"+str(proj_id)
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						add_params={}
						response_url=''
						if (discovery_status=="processing" and vul_scan_status=="incomplete") and (mode=="sequential" or mode=="sequential_default"):
							restore_discovery=True
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True','mode':mode}
						
							
						elif (((vul_scan_status=="processing" and discovery_status=="complete") and( mode=="sequential" or mode=="sequential_default")) or ((vul_scan_status=="complete" and discovery_status=="complete") and (mode=="sequential" or mode=="sequential_default") )):
							restore_scanning=True
							#api_url="/resume_scanning/"
							response_url="vul_scan.html"
							content_list=[]							
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",None,"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','skip':'true'}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							
						elif (vul_scan_status=="processing" and discovery_status=="complete" and mode=="concurrent") or (vul_scan_status=="complete" and discovery_status=="complete" and mode=="concurrent"):
							restore_both=True
							#api_url="/resume_conc/"
							response_url="concurrent.html"
							content_list=[]			
							#add_params["concurrent"]=True				
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",{"concurrent":"1"},"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','percentage':50}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
	
						elif discovery_status=="processing" and vul_scan_status=="processing":
							restore_both=True
							response_url="concurrent.html"
							content_list=[]			
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",{"concurrent":"1"},"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','percentage':50}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
	
						elif ((discovery_status=="complete" and vul_scan_status=="incomplete") and (mode=="sequential" or mode=="sequential_default")):
							restore_conf=True
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True','mode':mode}

						if restore_discovery or restore_scanning or restore_both or restore_conf:
								return render(request,response_url,add_params)
								
						else:
							error_msg='Can not Restore the current project with its current status -- Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'

			return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99"
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(eex)})
			except Exception ,ex:
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(ex)})

class Resume_Scan(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			proj_name=request.POST["project_name"];
			error_msg=''
			pause_discovery=False
			pause_scanning=False
			pause_both=False
			
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						add_params={}
						response_url=''
						if ((discovery_status=="paused" and vul_scan_status=="incomplete") and (mode=="sequential" or mode=="sequential_default")) :
							pause_discovery=True
							api_url="/resume/"
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True','mode':mode}
						elif discovery_status=="paused" and vul_scan_status=="incomplete" and mode=="concurrent" :
							pause_discovery=True
							api_url="/resume_conc/"
							response_url="concurrent.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True','percentage':0}
							
						elif ((vul_scan_status=="paused" and discovery_status=="complete") and (mode=="sequential" or mode=="sequential_default")):
							pause_scanning=True
							api_url="/resume_scanning/"
							response_url="vul_scan.html"
							content_list=[]							
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",None,"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','skip':'true'}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							
						elif vul_scan_status=="paused" and discovery_status=="complete" and mode=="concurrent":
							pause_scanning=True
							api_url="/resume_conc/"
							response_url="concurrent.html"
							content_list=[]			
							#add_params["concurrent"]=True				
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",{"concurrent":"1"},"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','percentage':50}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}

						elif discovery_status=="paused" and vul_scan_status=="paused" and mode=="concurrent":
							pause_both=True
							#api_url="/resume_conc/"
							api_url="/resume_conc/"
							response_url="concurrent.html"
							content_list=[]			
							#add_params["concurrent"]=True				
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",{"concurrent":"1"},"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False','percentage':0}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}


						if pause_discovery or pause_scanning or pause_both:
							#print "API URL IS :"+str(api_url)
							content_status=Custom().getApiContent(proj_id,api_url,None,"post")
							if content_status["status"]=="success":
								content=content_status["value"]
								#return render(request,response_url,{'project_id':proj_id,'project_name':proj_name,'error':'False','success':'True','project_status':'In Progress'})					
								return render(request,response_url,add_params)
							else:
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
						else:
							error_msg='Can not Resume the current project with its current status -- Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'

			return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99"
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(eex)})
			except Exception ,ex:
				return render(request,"scans.html",{'project_id':proj_id,'error':'True','success':'False','error_msg':str(ex)})


			
class Pause_Scan(LoginRequiredMixin,View):
	
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			
			#print "Obtained Project id :"+str(proj_id)
			error_msg=''
			pause_discovery=False
			pause_scanning=False
			pause_both=False
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						mode=stat_val["mode"]
						add_params={}
						if ((discovery_status=="processing" and vul_scan_status=="incomplete") and (mode=="sequential" or mode=="sequential_default")):
							pause_discovery=True
							api_url="/stop/"
							add_params=None
						elif discovery_status=="processing" and vul_scan_status=="incomplete" and mode=="concurrent":
							pause_both=True
							api_url="/stop_conc/"
							add_params["concurrent"]=True
						
						elif ((discovery_status=="complete" and vul_scan_status=="processing") and (mode=="sequential" or mode=="sequential_default")):
							pause_scanning=True
							api_url="/stop_scanning/"
							add_params["concurrent"]=False
						
						elif discovery_status=="complete" and vul_scan_status=="processing" and mode=="concurrent":
							pause_both=True
							api_url="/stop_conc/"
							add_params["concurrent"]=True

						elif discovery_status=="processing" and vul_scan_status=="processing" and mode=="concurrent":
							pause_both=True
							api_url="/stop_conc/"
							add_params["concurrent"]=True

						if pause_discovery or pause_scanning or pause_both:
							#print "API URL IS :"+str(api_url)
							content_status=Custom().getApiContent(proj_id,api_url,add_params,"post")
							if content_status["status"]=="success":
								content=content_status["value"]
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								error_msg='Some error occured at server '+str(content_status["value"])
								
						else:
							if discovery_status=="paused" or vul_scan_status=="paused":
								error_msg='The current project is already paused'
							else:
								error_msg='Can not Pause the current project with its current status -- Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'

			return JsonResponse({'project_id':proj_id,'error':'True','success':'False','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				#print "99"
				return JsonResponse({'project_id':proj_id,'error':'True','success':'False','error_msg':str(eex)})
			except Exception ,ex:
				return JsonResponse({'project_id':proj_id,'error':'True','success':'False','error_msg':str(ex)})

	
class Vul_Scan(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			th=request.POST["threading"];
			if th=="True":
				threading=True
			else:
				threading=False

			#print "Obtained Project id :"+str(proj_id)
			error_msg=''
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="complete" and vul_scan_status=="incomplete":
							content_status=Custom().getApiContent(proj_id,"/config_conc/")
							if content_status["status"]=="success":
								content=content_status["data"]
								scan_stat=Custom().getApiContent(proj_id,"/launch_scanning/",{'threading':threading},"post")
								if scan_stat["status"]=="success":
									return render(request,"vul_scan.html",{'project_id':proj_id,'project_status':'In Progress','content':content,'continue':'True'})
									
									
								else:
									error_msg="Cant start the scan due to following errors :"+str(scan_stat["value"])
							else:
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'

			return render(request,"vul_scan.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				#print "99"
				return render(request,"vul_scan.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101-Exception"+str(ex)
				return render(request,"vul_scan.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

			




class Discovery(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			proj_id=request.GET["proj_id"]
			proj_name=request.GET["proj_name"]
			mode_=request.GET["mode"]
			in_prog='In Progress'
			if proj_id !=None and proj_name !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="processing":
							percentage_status=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'discovery'})
							if percentage_status["status"]=="success":
								percentage=int(float(percentage_status["value"]))
								#print "Obtained percentage is :"+str(percentage)
								#url_="details_update
								if percentage ==100:
									percentage=99
									#in_prog='complete'
								return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':in_prog,'percentage':str(percentage),'continue':'True','mode':mode_})
							else:
								return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'Can not fetch percentage '+str(percentage_status["value"]),'continue':'False','mode':mode_})

						elif discovery_status=="complete":
							percentage="100"
							in_prog="complete"
							return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':in_prog,'percentage':str(100),'continue':'False','mode':mode_})
						else:
							percentage="0"
							in_prog="error"
							return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':'Cant fetch project state','continue':'False','mode':mode_})
					else:
						return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'Can not fetch project status '+str(resp_status["value"]),'continue':'False','mode':mode_})

				else:
						return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'You do not have the ownership of the selected project ','continue':'False','mode':mode_})

			else:
						return render(request,"details_update.html",{'project_id':'','project_name':'','error':'True','project_status':'error','error_msg':'Either of Project id or Project_name not supplied with input ','continue':'False','mode':mode_})

		except Exception ,eex:
			try:
				return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':str(eex),'mode':mode_})
			except Exception ,ex:
				return render(request,"details_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})



class Config_conc(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "Posted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			#mode=request.POST["mode"]
			#print "Obtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						pass_=False
						error_msg=''
						if (vul_scan_status=="processing" and discovery_status=="processing") or (vul_scan_status=="processing" and discovery_status =="complete") :
							
							content_status=Custom().getApiContent(proj_id,"/config/",{"data":data,"concurrent":"1","project_id":proj_id},"post")
							
							if content_status["status"]=="success":
								content=content_status["data"]
								updated_svc_list=content_status["value"] #List of dict
								if content[0]["status"]=="success":
									data_=content[0]["value"]
									#print "33"
									p_scan=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'scan'})			
									p_discovery=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'discovery'})

									if p_scan["status"]=="success" and p_discovery["status"]=="success":
										percentage_s=int(float(p_scan["value"]))
										percentage_d=int(float(p_discovery["value"]))
										#print "Obtained percentage is -- :"+str(percentage_s)+" and "  +str(percentage_d)
										#url_="details_update
										percentage=int((percentage_s + percentage_d)/2)
										if percentage ==100 :#or discovery_status=="complete":
											percentage=100
											in_prog='complete'
							
										return render(request,"concurrent_update.html",{'project_id':proj_id,'content':data_,'percentage':percentage,'project_status':'In Progress','updated_svc_list':updated_svc_list,'continue':'True'})
									else:
										error_msg="Cant fetch percentage "+str(p_scan["value"]) +"  "+str(p_discovery["value"])
	
								else:
									error_msg=str(content[0]["value"])
									
							else:
								#print "44"
								error_msg="Can not fetch Configuration "+str(content_status["value"])
								
						else:
							#print "55"
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
	
					else:
						#print "66"
						error_msg='Can not fetch project configuration '+str(resp_status["value"])
						
				else:
						#print "77"
						error_msg='You do not have the ownership of the selected project '
						
			else:
						#print "88"
						error_msg='Project id not supplied with input'

			return render(request,"concurrent_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':error_msg,'continue':'False'})
						
		except Exception ,eex:
				return render(request,"concurrent_update.html",{'project_id':'','project_status':'error','error':'True','error_msg':str(eex)})
			
class Add_Test_Case(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'
	
	def post(self,request):
		try:
			#print "Posted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			mode=request.POST["mode"]
			mode_error=False
			resp_url="reconfigure_update.html"
			conc="0"
			if mode not in ["sequential","concurrent"]:
				mode_error=True
			if mode =="sequential":
				resp_url="reconfigure_update.html"
				
			elif mode=="concurrent":
				resp_url="concurrent_update.html"
				conc="1"
			#print "Mode is : "+str(mode)
			if proj_id !=None and mode_error==False:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						pass_=False
						if (discovery_status=="complete" and vul_scan_status=="incomplete" and mode=="sequential") or  (discovery_status=="complete" and vul_scan_status=="incomplete" and mode=="concurrent") or (discovery_status=="processing" and vul_scan_status=="processing" and mode=="concurrent") or (discovery_status=="complete" and vul_scan_status=="processing" and mode=="concurrent"):
							content_status=Custom().getApiContent(proj_id,"/Add/",{"data":data,"concurrent":conc,"project_id":proj_id},"post")
							
							if content_status["status"]=="success":
								content=content_status["data"]
								updated_svc_list=content_status["value"] #List of dict
								if content[0]["status"]=="success":
									data_=content[0]["value"]
									if mode !="concurrent":
									
										return render(request,resp_url,{'project_id':proj_id,'content':data_,'updated_svc_list':updated_svc_list,'continue':'True'})
									else:
										p_scan=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'scan'})			
										p_discovery=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'discovery'})

										if p_scan["status"]=="success" and p_discovery["status"]=="success":
											percentage_s=int(float(p_scan["value"]))
											percentage_d=int(float(p_discovery["value"]))
											#print "Obtained percentage is -- :"+str(percentage_s)+" and "  +str(percentage_d)
											#url_="details_update
											percentage=int((percentage_s + percentage_d)/2)
											if percentage ==100 :#or discovery_status=="complete":
												percentage=100
												in_prog='complete'
							
											return render(request,resp_url,{'project_id':proj_id,'content':data_,'percentage':percentage,'project_status':'In Progress','updated_svc_list':updated_svc_list,'continue':'True'})
										else:
											error_msg="Cant fetch percentage "+str(p_scan["value"]) +"  "+str(p_discovery["value"])
									
								else:
									return render(request,resp_url,{'project_id':proj_id,'error':'True','project_status':'error','error_msg':content[0]["value"],'continue':'False','updated_svc':updated_svc_list})
							else:
								error_msg='Can not fetch Configuration '+str(content_status["value"])
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
	
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			return render(request,resp_url,{'project_id':proj_id,'error':'True','project_status':'error','error_msg':error_msg,'continue':'False','updated_svc':''})

		except Exception ,eex:
			try:
				print "	Exception 99--"+str(eex)
				return render(request,resp_url,{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101"
				return render(request,resp_url,{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})


class Config(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'
	
	def post(self,request):
		try:
			#print "Posted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			#mode=request.POST["mode"]
			#print "Obtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						pass_=False
						if (discovery_status=="complete" and vul_scan_status=="incomplete") :
							#print "22"
							content_status=Custom().getApiContent(proj_id,"/config/",{"data":data,"concurrent":"0","project_id":proj_id},"post")
							#print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nObtained Response is :"+str(content_status)
							if content_status["status"]=="success":
								content=content_status["data"]
								updated_svc_list=content_status["value"] #List of dict
								if content[0]["status"]=="success":
									data_=content[0]["value"]
									#print "33"
									return render(request,"reconfigure_update.html",{'project_id':proj_id,'content':data_,'updated_svc_list':updated_svc_list,'continue':'True'})
								else:
									return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':content[0]["value"],'continue':'False','updated_svc':updated_svc_list})
							else:
								#print "44"
								return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration '+str(content_status["value"]),'continue':'False'})
						else:
							#print "55"
							return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status,'continue':'False'})
	
					else:
						#print "66"
						return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch project configuration '+str(resp_status["value"]),'continue':'False'})

				else:
						#print "77"
						return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'You do not have the ownership of the selected project ','continue':'False'})

			else:
						#print "88"
						return render(request,"reconfigure_update.html",{'project_id':'','project_name':'','error':'True','project_status':'error','error_msg':'Project id not supplied with input ','continue':'False'})

		except Exception ,eex:
			try:
				print "Exception ---- 99"
				return render(request,"reconfigure_update.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "EXception -101"
				return render(request,"reconfigure_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})


	
	def get(self,request):
		try:
			proj_id=request.GET["proj_id"]
			#proj_name=request.GET["proj_name"]
			in_prog='In Progress'
			#print "inside config view"
			if proj_id and proj_id !=None :
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="complete" and vul_scan_status=="incomplete":
							content_status=Custom().getApiContent(proj_id,"/config/")
							if content_status["status"]=="success":
								#print "all looks fine "
								content=content_status["data"]
								return render(request,"reconfigure.html",{'project_id':proj_id,'content':content,'continue':'True'})
							else:
								return render(request,"reconfigure.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration '+str(content_status["value"]),'continue':'False'})
						else:
							return render(request,"reconfigure.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status,'continue':'False'})
	
					else:
						return render(request,"reconfigure.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch project configuration '+str(resp_status["value"]),'continue':'False'})

				else:
						return render(request,"reconfigure.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'You do not have the ownership of the selected project ','continue':'False'})

			else:
						return render(request,"reconfigure.html",{'project_id':'','project_name':'','error':'True','project_status':'error','error_msg':'Project id not supplied with input ','continue':'False'})

		except Exception ,eex:
			try:
				return render(request,"reconfigure.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				return render(request,"reconfigure.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

class Profiles_(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

		
	def get(self,request):
		try:
			user_obj=Profile.objects.get(user_id=request.user.id)
			print "Well user is : "+str(user_obj.id)
			print str(type(user_obj))
			content_status=ScanProfiles().getAll(user_obj)
			key="load"
			if content_status != -1:
				all_json=content_status["All_json"]
				master_json=content_status["Master_json"]
				mandatory_json=content_status["Mandatory_json"]
				analytical_json=content_status["Analytical_json"]
				mapper_json=content_status["Mapper_json"]
				custom_profiles=content_status["Custom_json"]
				print "Type is : "+str(type(custom_profiles))
				mandatory_mapped={}
				analytical_mapped={}
				mandatory_mapped=ScanProfiles().Map(mandatory_json,mapper_json)
				analytical_mapped=ScanProfiles().Map(analytical_json,mapper_json)
				master_mapped=ScanProfiles().Map(master_json,mapper_json)
				print "Recieved length of Cusstom profile : " +str(len(custom_profiles))
				#for p in custom_profiles:
				#	print "Profile is : "+str(type(p))
				#print custom_profiles[0]
				print "\n\n\n"
				return render(request,"profiles.html",{'master_json':master_mapped,'mandatory_json':mandatory_mapped,'analytical_json':analytical_mapped,'m_json':json.dumps(mandatory_json),'a_json':json.dumps(analytical_json),'ms_json':json.dumps(master_json),'custom_profile':custom_profiles,"key":key})
			else:
				print "heeee"
				return render(request,"profiles.html",{'success':'False','error':'True','error_msg':'Some error occured while fetching the Profiles','master_json':'','mandatory_json':'','analytical_json':'','m_json':'','a_json':'','ms_json':'','custom_profile':''})
		except Exception ,exc:
			print str(exc)
			return render(request,"profiles.html",{'success':'False','error':str(exc),'error_msg':str(exc),'master_json':'','mandatory_json':'','analytical_json':'','m_json':'','a_json':'','ms_json':'','custom_profile':''})

	#{"app_key":"","project_name":"","IP_range":"","Port_range":"","switch":"","assessment_id":""}'
	def post(self ,request):
		try:
			api_address=Custom().get_api_address()
			form_attr=ProfileAttributes(request.POST)
			if form_attr.is_valid():
				ass_id=Custom().generate_uuid()
				user_obj=Profile.objects.get(user_id=request.user.id)
				Profiles.objects.create(user=user_obj,profile_id='',assessment_id=str(ass_id))				
				api_key=getattr(settings,'API_KEY',None)
				app_id=getattr(settings,'APP_ID',None)
				#scan_mode=form_attr.cleaned_data["Mode"]
				data = {"app_key" : api_key,"profile_name":form_attr.cleaned_data["Profile_name"],
				"assessment_id":str(ass_id),"app_id":str(app_id),"profile_id":form_attr.cleaned_data["profile_value"],"profile_json":form_attr.cleaned_data["profile_json"]}

				url = api_address +"/ScanProfiles/"
					
				
				data_json = json.dumps(data)
				headers = {'Content-type': 'application/json'}
				response = requests.post(url, data=data_json, headers=headers)
				resp={}
				resp=json.loads(str(response.json()))	
				if resp["status"]=="success":
					#print "Success"
					profile_obj=Profiles.objects.get(user=user_obj,assessment_id=str(ass_id))
					profile_obj.profile_id=resp["value"]
					profile_obj.save()
					return redirect('/ScanProfiles?success=True&success_msg=Profile_Created')
					#return render(request,"profiles.html",{'profile_id':resp["value"],'profile_name':form_attr.cleaned_data["Profile_name"],'success':'True','success_msg':'Profile Saved'})
					
				else:			
					return render(request,"profiles.html",{'success':'False','error':resp["value"]})
			else:
				#print "Inside errors !!"
				return render(request,"profiles.html",{'success':'False','error':'Validation errors','form':form_attr})

		except Exception ,eex:
			print "Exception @:"+str(eex)
			return render(request,"profiles.html",{'success':'False','error':str(eex)})


		
	

class Profile_(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

		
	def get(self,request):
		try:
			user_obj=Profile.objects.get(user_id=request.user.id)
			ret_response={}
			print "1222"
			if (Custom().getOwnershipProfile(request.GET["profile_id"],user_obj)):
				id_list=[]
				id_list.append(int(request.GET["profile_id"]))
				#print "id list is : "+str(id_list)
				content_status=ScanProfiles().getOne(id_list)
				#print content_status
				if content_status != -1:
					custom_profiles=content_status["Custom_json"]["data"]
					mapper_json=content_status["Mapper_json"]
					ret_response["status"]="success"
					#ret_response["value"]=custom_profiles
					custom_mapped=ScanProfiles().Map(custom_profiles,mapper_json)
					ret_response["value"]=custom_mapped
					ret_response["custom_json"]=custom_profiles
					ret_response["name"]=content_status["Custom_json"]["name"]
					#print "Custom mapped is : " +str(custom_mapped)
					return JsonResponse(ret_response)
				else:
					ret_resp={}
					ret_resp["status"]="failure"
					ret_resp["value"]="Some error occured at server "
					return JsonResponse(ret_resp)

			else:
					ret_resp={}
					ret_resp["status"]="failure"
					ret_resp["value"]="You dont have ownership on this scan profile "
					return JsonResponse(ret_resp)

		except Exception ,exc:
			print "EXception !@"+str(exc)
			return JsonResponse({'status':'failure','error':str(exc)})

	def post(self,request):
		try:
			user_obj=Profile.objects.get(user_id=request.user.id)
			ret_response={}
			print "1"
			if (Custom().getOwnershipProfile(request.POST["profile_id"],user_obj)):
				content_status=Custom().getApiContent('',"/ScanProfile/",{'profile_id':request.POST["profile_id"]},"post")
				if content_status["status"]=="success":
					profile_obj=Profiles.objects.get(profile_id=str(request.POST["profile_id"]))
					profile_obj.profile_catagory="Shared"
					profile_obj.save()
				return JsonResponse(content_status)
				
			else:
					ret_resp={}
					ret_resp["status"]="failure"
					ret_resp["value"]="You dont have ownership on this scan profile "
					return JsonResponse(ret_resp)

		except Exception ,exc:
			print "EXception "+str(exc)
			return JsonResponse({'status':'failure','error':str(exc),'value':str(exc)})


class Scan(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get_switches(self):	
		switch_list=[]
		content_status=Custom().getApiContent('',"/switches/")
		if content_status["status"]=="success":
			content=content_status["value"]
			switch_list=content
			return switch_list
		else:
			#print "value is :" +str(content_status["value"])
			switch["id"]=1
			switch["name"]="Intense Scan"
			switch_list.append(switch)
			return switch_list 

		
	def get(self,request):
		user_obj=Profile.objects.get(user_id=request.user.id)
		#print "Well user is : "+str(user_obj.id)
		#print str(type(user_obj))
		content_status=ScanProfiles().getAll(user_obj)
			
		#content_status=ScanProfiles().getAll()
		if content_status != -1:
			all_json=content_status["All_json"]
			master_json=content_status["Master_json"]
			mandatory_json=content_status["Mandatory_json"]
			analytical_json=content_status["Analytical_json"]
			mapper_json=content_status["Mapper_json"]
			mandatory_mapped={}
			analytical_mapped={}
			mandatory_mapped=ScanProfiles().Map(mandatory_json,mapper_json)
			analytical_mapped=ScanProfiles().Map(analytical_json,mapper_json)
			master_mapped=ScanProfiles().Map(master_json,mapper_json)
			custom_profiles=content_status["Custom_json"]
			#print "Len of custom profile : " +str(len(custom_profiles))			
		return render(request,"scan.html",{'switches':self.get_switches(),'master_json':master_mapped,'custom_profile':custom_profiles,'mandatory_json':mandatory_mapped,'analytical_json':analytical_mapped,'m_json':json.dumps(mandatory_json),'a_json':json.dumps(analytical_json),'ms_json':json.dumps(master_json)})

	#{"app_key":"","project_name":"","IP_range":"","Port_range":"","switch":"","assessment_id":""}'
	def post(self ,request):
		try:
			api_address=Custom().get_api_address()
			form_attr=ScanAttributes(request.POST)
			user_obj=Profile.objects.get(user_id=request.user.id)
			#if 
			if (form_attr.is_valid() and (Custom().getOwnershipProfile(request.POST["profile_value"],user_obj))):
				#print "Form is valid !!!"
				ass_id=Custom().generate_uuid()
				
				Projects.objects.create(user=user_obj,project_id='',assessment_id=str(ass_id))				
				#print "Created Assessment id successfully"
				
				api_key=getattr(settings,'API_KEY',None)
				app_id=getattr(settings,'APP_ID',None)
				scan_mode=form_attr.cleaned_data["Mode"]
				print "Edit profile is : "+str(form_attr.cleaned_data["edit_profile"])
				data = {"app_key" : api_key,"project_name":form_attr.cleaned_data["Project_name"],
				"IP_range":form_attr.cleaned_data["Ip_range"],"Port_range":form_attr.cleaned_data["Port_range"],
				"switch":form_attr.cleaned_data["Switch"],"assessment_id":str(ass_id),"mode":scan_mode,"app_id":str(app_id),"profile":form_attr.cleaned_data["profile_value"],"profile_json":form_attr.cleaned_data["profile_json"],"edit_profile":form_attr.cleaned_data["edit_profile"]}

				if scan_mode=="sequential" or scan_mode=="sequential_default":
					url = api_address +"/scan/"
					
				elif scan_mode =="concurrent":
					url = api_address +"/scan_concurrent/"
				
				else:
					return render(request,"scan.html",{'success':'False','error':"Invalid scan mode"})
				
				data_json = json.dumps(data)
				headers = {'Content-type': 'application/json'}
				response = requests.post(url, data=data_json, headers=headers)
				#print "Response obtained is :"+str(response)	
				resp={}
				resp=json.loads(str(response.json()))	
				#print "Updated Json format is : "+str(resp)	
				if resp["status"]=="success":
					#print "Success"
					project_obj=Projects.objects.get(user=user_obj,assessment_id=str(ass_id))
					project_obj.project_id=resp["value"]
					project_obj.save()
					if (int(form_attr.cleaned_data["edit_profile"])==1):
						p_id=resp["profile_id"]
						Profiles.objects.create(user=user_obj,profile_id=p_id,assessment_id=str(ass_id),profile_catagory="Project_Specific")
						print "Profile saved !!!!"
					if scan_mode=="sequential" or scan_mode=="sequential_default":
						return render(request,"details.html",{'project_id':resp["value"],'project_name':form_attr.cleaned_data["Project_name"],'project_status':'In Progress','mode':scan_mode})
					elif scan_mode=="concurrent":
						return render(request,"concurrent.html",{'project_id':resp["value"],'project_name':form_attr.cleaned_data["Project_name"],'project_status':'In Progress','percentage':0})
					else:
						return render(request,"scan.html",{'success':'False','error':"Invalid scan mode"})
				else:
					#print "Failure"				
					return render(request,"scan.html",{'success':'False','error':resp["value"]})
			else:
				print "Inside errors !!"
				user_obj=Profile.objects.get(user_id=request.user.id)
				content_status=ScanProfiles().getAll(user_obj)
			
				#content_status=ScanProfiles().getAll()
				if content_status != -1:
					all_json=content_status["All_json"]
					master_json=content_status["Master_json"]
					mandatory_json=content_status["Mandatory_json"]
					analytical_json=content_status["Analytical_json"]
					mapper_json=content_status["Mapper_json"]
					mandatory_mapped={}
					analytical_mapped={}
					mandatory_mapped=ScanProfiles().Map(mandatory_json,mapper_json)
					analytical_mapped=ScanProfiles().Map(analytical_json,mapper_json)
					master_mapped=ScanProfiles().Map(master_json,mapper_json)
					custom_profiles=content_status["Custom_json"]
				return render(request,"scan.html",{'success':'False','error':'Validation errors /Ownership Errors','form':form_attr,'switches':self.get_switches(),'master_json':master_mapped,'custom_profile':custom_profiles,'mandatory_json':mandatory_mapped,'analytical_json':analytical_mapped,'m_json':json.dumps(mandatory_json),'a_json':json.dumps(analytical_json),'ms_json':json.dumps(master_json)})

		except Exception ,eex:
			print "Exception @:"+str(eex)
			return render(request,"scan.html",{'success':'False','error':str(eex),'switches':self.get_switches()})



class Polling_Scanning_conc(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "\n\n\n\n\nPosted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			source=request.POST["source"];
			#print "\n\n\n\n\n\n\n\nObtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if (vul_scan_status=="processing" and discovery_status=="processing") or (vul_scan_status=="processing" and discovery_status =="complete") or (vul_scan_status=="complete" and discovery_status =="complete") :
							content_status={}
							content_status["status"]="failure"
							content_status["value"]="Invalid source choice : "+str(source)
							#print "Obtained source is :"+str(source)
							if source=="final":
								content_status=Custom().getApiContent(proj_id,"/polling_scanning/",{"record_list":data,"project_id":proj_id},"post")
							elif source=="init":
								content_status=Custom().getApiContent(proj_id,"/polling/",{"record_list":data,"project_id":proj_id},"post")
							
							if content_status["status"]=="success":
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								#print "44"
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			#print "Error msg is --->:"+error_msg
			return JsonResponse({'project_id':proj_id,'project_status':'error','success':'False','error':'True','error_msg':error_msg})

		except Exception ,eex:
			try:
				#print "99-Indide exception"+str(eex)
				return JsonResponse({'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				#print "101"
				return JsonResponse({'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

	def get(self,request):
		try:
			#print "Posted"
			proj_id=request.GET["proj_id"];
			error_msg=''
			in_prog="In Progress"
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if (vul_scan_status=="processing" and discovery_status=="processing") or (vul_scan_status=="processing" and discovery_status =="complete") or (vul_scan_status=="complete" and discovery_status =="complete") :
							if discovery_status=="complete":
								a=333
								#is_empty=Custom().getApiContent(proj_id,"/is_empty_discovery/")
								#if is_empty["status"]=="success" and is_empty["value"] ==True :
								#	a=222
								#	print "Discovery discovered no running service"
							p_scan=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'scan'})			
							p_discovery=Custom().getApiContent(proj_id,"/percentPolling/",{'source':'discovery'})

							if p_scan["status"]=="success" and p_discovery["status"]=="success":
								percentage_s=int(float(p_scan["value"]))
								percentage_d=int(float(p_discovery["value"]))
								#print "Obtained percentage is :"+str(percentage_s)+" and "  +str(percentage_d)
								#url_="details_update
								percentage=int((percentage_s + percentage_d)/2)
								#print "Final %age :"+str(percentage)
								if percentage ==100 :#or discovery_status=="complete":
									percentage=100
									in_prog='complete'
								rec_complete=Custom().getApiContent(proj_id,"/polling/")
								source=""
								content_status=Custom().getApiContent(proj_id,"/polling_scanning/")
								if content_status["status"]=="success" or rec_complete["status"]=="success":
										rec_list=[]
										if content_status["status"]=="success":
											content=content_status["data"]
											rec_list=content_status["record_list"]
											source="final"
										else:
											content=-1
											rec_list=rec_complete["record_list"]
											source="init"
										config_=Custom().getApiContent(proj_id,"/config_conc/")

										if (config_["status"]=="success"):
											content_list=[]
											if content != -1:
												
												for c in content:
													#print "Content id is :"+str(c["id"])
													#print "command is"
													formatted_data=Custom().format_data(c["Commands"])
													if formatted_data == -1:
															formatted_data="No data can be fetched !!"
													#print "reached here "+str(c["id"])
													content_list.append({"id":c["id"],"Commands":formatted_data})
											return render(request,"concurrent_update.html",{'project_id':proj_id,'percentage':percentage,'content':config_["data"],'updated_content':content_list,'continue':'True','source':source,'change_contentt':'True','record_list':rec_list,'project_status':in_prog})
										else:
											#print "OOPS failure "
											error_msg='Some failure occured while fetching Configuration : '+str(config_["value"])
								#In the foll handel the case where the discovery of service would be nothing for a host.IN such a case the user must get some sort of message

								elif content_status["status"]=="empty" and rec_complete["status"]=="empty":
										#print "Empty"
										return render(request,"concurrent_update.html",{'project_id':proj_id,'percentage':percentage,'continue':'True','change_contentt':'False','project_status':in_prog})
								elif content_status["status"]=="failure" and rec_complete["status"]=="failure":
										error_msg='Some failure occured while fetching vul scan results --> '+str(content_status["value"]) + str(rec_complete["value"])
								elif content_status["status"]== "faliure" or rec_complete["status"]=="failure":
									if rec_complete["status"]=="failure":
										error_msg='Some failure occured while fetching vul scan results' + str(rec_complete["value"])
									else:
										error_msg='Some failure occured while fetching vul scan results ' + str(rec_complete["value"])
								
					
									
							else:
								error_msg='Can not fetch Percentage for current Project '+str(p_scan["value"]+"   " +p_discovery["value"])
								
						else:
							#print "Here i am "
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project status '+str(resp_status["value"])
						
				else:
						error_msg='You do not have the ownership of the selected project '
						
			else:
						error_msg='Project id not supplied with input'
		
			#print "Returning"
			#print "Returninhg error :"+error_msg
			return render(request,"concurrent_update.html",{'project_id':proj_id,'project_status':'error','error':'True','change_contentt':'True','error_msg':error_msg})
						
		except Exception ,eex:
			try:
				print "99-----"+str(eex)
				return render(request,"concurrent_update.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex),'change_contentt':'True'})
			except Exception ,ex:
				print "101"
				return render(request,"concurrent_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','change_content':'True','error_msg':"No project Found--"+str(ex)})


class Vul_Scan_conc(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			#print "\n\n\n\n\nPosted"
			data=json.loads(request.POST["data"]);
			#print "Obtained data is :-->"+str(data)
			proj_id=request.POST["project_id"];
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if (vul_scan_status=="processing" and discovery_status=="processing") or (vul_scan_status=="processing" and discovery_status =="complete") :
							content_status=Custom().getApiContent(proj_id,"/launch_scanning_concurrent/",{"record_list":data,"project_id":proj_id,"threading":False},"post")
							#print "The obtained value from server for conc mode is :"+str(content_status)
							
							if content_status["status"]=="success":
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								#print "44"
								error_msg='Can not start Scanning because of following errors '+str(content_status["value"])
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			#print "Error msg is --->:"+error_msg
			return JsonResponse({'project_id':proj_id,'project_status':'error','success':'False','error':'True','error_msg':error_msg})

		except Exception ,eex:
			try:
				print "99-Indide exception"+str(eex)
				return JsonResponse({'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				#print "101"
				return JsonResponse({'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})


class Upload(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			final_list=[]
			final_list=Custom().getProjects(request)
			if final_list != -1:
						
				return render(request,"upload.html",{'projects':final_list,'error':'False'})
			else:
				return render(request,"upload.html",{'error_msg':"Some error occured while fetching projects",'error':'True','success':'False'})			
			
			#return render(request,"upload.html",{})
		except Exception ,exc:
			return render(request,"upload.html",{'project_status':'error','error':'True','error_msg':str(exc),"success":'False'})


	def post(self,request):
		try:
			final_list=[]
			final_list=Custom().getProjects(request)
			skip_ownership_check=False
			if final_list ==-1:
				final_list=""
				
			xml_file=request.FILES.get('file', None)
			try:
				project =request.POST["project"]
				source=request.POST["source"]
			except KeyError:
				project=""
				source=""
			if xml_file ==None or project =="":
				return render(request,"upload.html",{'project_status':'error','error':'True','error_msg':"Project Name/Id and XML file Required","success":'False','projects':final_list})
				
			else:
				#print "In else not ret error"
				if source=="nmap":
					api_url="/upload/"
					ass_id=Custom().generate_uuid()
					user_obj=Profile.objects.get(user_id=request.user.id)
					Projects.objects.create(user=user_obj,project_id='',assessment_id=str(ass_id))		
					skip_ownership_check=True		
					#print "Created Assessment id successfully"
					app_id=getattr(settings,'APP_ID',None)
					add_params= {"project_name":project,"assessment_id":str(ass_id),"app_id":app_id}
					
				elif source=="nessus":
					api_url="/uploadNessus/"
					add_params= {"project_name":project}
				elif source=="qualys":
					api_url="/uploadQualys/"
					add_params= {"project_name":project}
				else:
					
					return render(request,"upload.html",{'project_status':'error','error':'True','error_msg':"Source can be only nmap ,qualys or nessus","success":'False','projects':final_list})
				
				if skip_ownership_check==False:
					user_obj=Profile.objects.get(user_id=request.user.id)
					if Custom().getOwnership(project,user_obj)==False:
						return render(request,"upload.html",{'project_status':'error','error':'True','error_msg':"You do not have ownership over the current  project","success":'False','projects':final_list})
				
				files={'filename':xml_file.read()}
				
				resp=Custom().getApiContent(project,api_url,add_params,"post",files)
	
				if resp["status"]=="success":
					if source =="nmap":
						project_obj=Projects.objects.get(user=user_obj,assessment_id=str(ass_id))
						project_obj.project_id=resp["value"]
						project_obj.save()
					
					return render(request,"upload.html",{'error':'False','success_msg':"Report Uploaded successfully","success":'True','projects':final_list})

				else:
					return render(request,"upload.html",{'project_status':'error','error':'True','error_msg':"Report Upload Failed --"+str(resp["value"]),"success":'False','projects':final_list})		
					
				
        
		except Exception ,ex:
			return render(request,"upload.html",{"success":'False','project_status':'error','error':'True','error_msg':"Exception :"+str(ex),'projects':final_list})


class OnFly(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
						
				return render(request,"onFly.html",{'error':'False'})
			
		except Exception ,exc:
			return render(request,"onFly.html",{'project_status':'error','error':'True','error_msg':str(exc),"success":'False'})

	
	def post(self,request):
		try:
				
			try:
				source =request.POST["source"]
				format_=request.POST["format"]
				xml_file=request.FILES.get('file', None)
			except KeyError:
				project=""
				source=""
	
			if format_=="" or  source =="" or source not in ["nessus","qualys"] or format_ not in ["html","csv","xml","json"] or xml_file==None:
				return render(request,"onFly.html",{'project_status':'error','error':'True','error_msg':"Xml file and Report Format Required","success":'False'})
				
			else:
					
					files={'filename':xml_file.read()}
					add_params={"report_format":format_,"source":source}
					respp=Custom().getApiContent('',"/reportOnFly/",add_params,"post",files,"zip")
					
					if respp != -1:
						un_id=uuid.uuid1()
						file_name="On_Fly_uid:"+str(un_id)+".zip"
						file_path=os.path.join("Uploads",file_name)
						with open (file_path,'wb') as out_file:
								out_file.write(respp)

						zip_file=open(file_path,'rb')

						resp=HttpResponse(FileWrapper(zip_file),content_type="application/zip")
						resp['content-Disposition']='attachment;filename="%s"'%file_name
						os.remove(file_path)
						return resp
					else:
						return render(request,"onFly.html",{"success":'False','project_status':'error','error':'True','error_msg':"Some error occured while downloading  report"})

					
				
        
		except Exception ,ex:
			return render(request,"onFly.html",{"success":'False','project_status':'error','error':'True','error_msg':"Exception :"+str(ex),'projects':final_list})


class Merger(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			final_list=[]
			final_list=Custom().getProjects(request)
			if final_list != -1:
						
				return render(request,"merger.html",{'projects':final_list,'error':'False'})
			else:
				return render(request,"merger.html",{'error_msg':"Some error occured while fetching projects",'error':'True','success':'False'})			
			
			#return render(request,"merger.html",{})
		except Exception ,exc:
			return render(request,"merger.html",{'project_status':'error','error':'True','error_msg':str(exc),"success":'False'})

	
	def post(self,request):
		try:
			final_list=[]
			final_list=Custom().getProjects(request)
			#skip_ownership_check=False
			if final_list ==-1:
				final_list=""
				
			try:
				project =request.POST["project"]
				format_=request.POST["format"]
			except KeyError:
				project=""
				format_=""
	
			if format_=="" or  project =="" or format_ not in ["html","csv","xml","json"]:
				return render(request,"merger.html",{'project_status':'error','error':'True','error_msg':"Project Id and Report Format Required","success":'False','projects':final_list})
				
			else:
					user_obj=Profile.objects.get(user_id=request.user.id)
					if Custom().getOwnership(project,user_obj)==False:
						return render(request,"merger.html",{'project_status':'error','error':'True','error_msg':"You do not have ownership over the current  project","success":'False','projects':final_list})
					
					respp=Custom().getApiContent(project,"/mergeReports/",{"report_format":format_},"post",None,"zip")
					if respp != -1:
						un_id=uuid.uuid1()
						file_name=str(project)+"_uid:"+str(un_id)+".zip"
						file_path=os.path.join("Uploads",file_name)
						with open (file_path,'wb') as out_file:
								out_file.write(respp)

						zip_file=open(file_path,'rb')

						resp=HttpResponse(FileWrapper(zip_file),content_type="application/zip")
						resp['content-Disposition']='attachment;filename="%s"'%file_name
						os.remove(file_path)
						return resp
					else:
						return render(request,"merger.html",{"success":'False','project_status':'error','error':'True','error_msg':"Some error occured while downloading merged report",'projects':final_list})

					
				
        
		except Exception ,ex:
			return render(request,"merger.html",{"success":'False','project_status':'error','error':'True','error_msg':"Exception :"+str(ex),'projects':final_list})


class DownloadAll_im(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			proj_id=request.POST["project_id"];
			error_msg=""
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if (vul_scan_status=="processing" and discovery_status=="complete") or(vul_scan_status=="complete" and discovery_status=="complete") :
								respp=Custom().getApiContent(proj_id,"/downloadAll/",None,"post",None,"zip")
								if respp != -1:
									un_id=uuid.uuid1()
									file_name=str(proj_id)+"_uid:"+str(un_id)+".zip"
									file_path=os.path.join("Uploads",file_name)
									with open (file_path,'wb') as out_file:
											out_file.write(respp)

									zip_file=open(file_path,'rb')

									resp=HttpResponse(FileWrapper(zip_file),content_type="application/zip")
									resp['content-Disposition']='attachment;filename="%s"'%file_name
									os.remove(file_path)
									return resp
								else:
									error_msg="Some error occured while downloading report"

							
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			
			return render(request,"scans.html",{'error_msg':error_msg,'error':'True','success':'False'})


		except Exception ,eex:
			return render(request,"scans.html",{'error_msg':str(eex),'error':'True','success':'False'})


class DownloadAll(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			proj_id=request.POST["project_id"];
			error_msg=""
			if proj_id !=None:
				user_obj=Profile.objects.get(user_id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if (vul_scan_status=="complete" and discovery_status=="complete") :
								respp=Custom().getApiContent(proj_id,"/downloadAll/",None,"post",None,"zip")
								if respp != -1:
									un_id=uuid.uuid1()
									file_name=str(proj_id)+"_uid:"+str(un_id)+".zip"
									file_path=os.path.join("Uploads",file_name)
									with open (file_path,'wb') as out_file:
											out_file.write(respp)

									zip_file=open(file_path,'rb')

									resp=HttpResponse(FileWrapper(zip_file),content_type="application/zip")
									resp['content-Disposition']='attachment;filename="%s"'%file_name
									os.remove(file_path)
									return resp
								else:
									error_msg="Some error occured while downloading merged report"

							
								
						else:
							error_msg='Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status
							
					else:
						error_msg='Can not fetch project configuration '+str(resp_status["value"])

				else:
						error_msg ='You do not have the ownership of the selected project '

			else:
						error_msg='Project id not supplied with input '
			
			return render(request,"scans.html",{'error_msg':error_msg,'error':'True','success':'False'})


		except Exception ,eex:
			return render(request,"scans.html",{'error_msg':str(eex),'error':'True','success':'False'})



		
