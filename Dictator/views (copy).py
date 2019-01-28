from django.shortcuts import render
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
import requests
import pprint
import json
from .forms import ScanAttributes
import uuid
from .models import *
from log.models import *
#from local_settings import API_KEY
from django.conf import settings
from django.http import JsonResponse
from ansi2html_ import ansi2html
import ast
# Create your views here.


class Custom:
	def get_api_address(self):
		return "http://127.0.0.1:8002"

	def generate_uuid(self):
		return uuid.uuid1()

	def getOwnership(self,project_id,user_obj):
		if user_obj.user_role and user_obj.user_role=='admin':
			print "Current User is admin :"
			return True
		
		project_obj=Projects.objects.get(user=user_obj,project_id=str(project_id))
		print "Obtained Project obj is :"+str(project_obj)
		print "User not admin" +str(project_obj)
		if project_obj and project_obj !=None:
			return True
		else:
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
		
	def getApiContent(self,project_id,api_extention,add_params=None,request_type="get"):
		api_url=self.get_api_address()
		api_url=api_url+api_extention
		api_key=getattr(settings,'API_KEY',None)
		app_id=getattr(settings,'APP_ID',None)				
		data = {"app_key" : api_key,"project_id":project_id}
		if add_params !=None:
			#print "Recieved add params are :"+str(add_params)
			data.update(add_params)
		data_json = json.dumps(data)
		#print "Transformmed data to be sent :"+str(data_json)
		headers = {'Content-type': 'application/json'}
		if request_type=="get":
			response = requests.get(api_url, data=data_json, headers=headers)
		else:
			response = requests.post(api_url, data=data_json, headers=headers)
		#print "Response obtained is :"+str(response)	
		resp={}
		resp=json.loads(str(response.json()))	
		#print "Updated Json format of response is : "+str(resp)	
		return resp 
	

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
				user_obj=Profile.objects.get(id=request.user.id)
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
			print "Error msg is --->:"+error_msg
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
			print "Posted"
			proj_id=request.GET["proj_id"];
			error_msg=''
			in_prog="In Progress"
			if proj_id !=None:
				user_obj=Profile.objects.get(id=request.user.id)
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
								print "Obtained percentage is :"+str(percentage)
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
										print "\n\n\nI have obtained config !!!\n\n"
										if (config_["status"]=="success"):
											content_list=[]
											for c in content:
												print "Content id is :"+str(c["id"])
												print "command is"
												#print str(c["Commands"])

												formatted_data=Custom().format_data(c["Commands"])
												if formatted_data == -1:
														formatted_data="No data can be fetched !!"
												print "reached here "+str(c["id"])
												content_list.append({"id":c["id"],"Commands":formatted_data})
											return render(request,"vul_scan_update.html",{'project_id':proj_id,'percentage':percentage,'content':config_["data"],'updated_content':content_list,'continue':'True','change_contentt':'True','record_list':content_status["record_list"],'project_status':in_prog})
										else:
											print "OOPS failure "
											error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])

								elif content_status["status"]=="empty":
										return render(request,"vul_scan_update.html",{'project_id':proj_id,'percentage':percentage,'content':'','continue':'True','change_contentt':'False','project_status':in_prog})
								else:
										error_msg='Some failure occured while fetching vul scan results --> '+str(content_status["value"])
								
					
									
							else:
								error_msg='Can not fetch Percentage for current Project '+str(content_status["value"])
								
						else:
							print "Here i am "
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
			print "value of P is : "+str(p)
			content_status=Custom().getApiContent('',"/projects/",{"paused":p})
			if content_status["status"]=="success":
				user_obj=Profile.objects.get(id=request.user.id)
				if user_obj.user_role and user_obj.user_role =='admin':
					print "If cond is true"
					return render(request,"scans.html",{'data':content_status["data"],'error':'False','success':'True'})
		
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
						#print "appended"
				return render(request,"scans.html",{'data':final_list,'error':'False','success':'True'})
			else:
				return render(request,"scans.html",{'error_msg':content_status["value"],'error':'True','success':'False'})			
			
		except Exception ,eex:
			return render(request,"scans.html",{'error_msg':str(eex),'error':'True','success':'False'})


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
			restore_config=False
			
			if proj_id !=None:
				user_obj=Profile.objects.get(id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						add_params={}
						response_url=''
						if discovery_status=="processing" and vul_scan_status=="incomplete" :
							restore_discovery=True
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True'}
							
						elif vul_scan_status=="processing" and discovery_status=="complete" :
							restore_scanning=True
							#api_url="/resume_scanning/"
							response_url="vul_scan.html"
							content_list=[]							
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",None,"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False'}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							
							
						elif discovery_status=="processing" and vul_scan_status=="processing":
							restore_both=True
							#api_url="/resume_conc/"
							add_params["concurrent"]=True
						elif discovery_status=="complete" and vul_scan_status=="incomplete":
							restore_conf=True
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True'}

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
				user_obj=Profile.objects.get(id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						add_params={}
						response_url=''
						if discovery_status=="paused" and vul_scan_status=="incomplete" :
							pause_discovery=True
							api_url="/resume/"
							response_url="details.html"
							add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','error':'False','success':'True'}
							
						elif vul_scan_status=="paused" and discovery_status=="complete" :
							pause_scanning=True
							api_url="/resume_scanning/"
							response_url="vul_scan.html"
							content_list=[]							
							update_status=Custom().getApiContent(proj_id,"/scanning_st_up/",None,"post")
							if update_status["status"]=="success":
								config_=Custom().getApiContent(proj_id,"/config_conc/")
								if (config_["status"]=="success"):
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'In Progress','content':config_["data"],'continue':'True','error':'False'}								
								else:
									error_msg='Some failure occured while fetching Configuration --> '+str(config_["value"])
									add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							else:
								error_msg='Some failure occured while Updating status --> '+str(update_status["value"])
								add_params={'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':error_msg}
							
							
						elif discovery_status=="paused" and vul_scan_status=="paused":
							pause_both=True
							api_url="/resume_conc/"
							add_params["concurrent"]=True

						if pause_discovery or pause_scanning or pause_both:
							print "API URL IS :"+str(api_url)
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
			print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			
			print "Obtained Project id :"+str(proj_id)
			error_msg=''
			pause_discovery=False
			pause_scanning=False
			pause_both=False
			if proj_id !=None:
				user_obj=Profile.objects.get(id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						#print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						add_params={}
						if discovery_status=="processing" and vul_scan_status=="incomplete":
							pause_discovery=True
							api_url="/stop/"
							add_params=None
						elif discovery_status=="complete" and vul_scan_status=="processing":
							pause_scanning=True
							api_url="/stop_scanning/"
							add_params["concurrent"]=False
						elif discovery_status=="processing" and vul_scan_status=="processing":
							pause_both=True
							api_url="/stop_conc/"
							add_params["concurrent"]=True
						if pause_discovery or pause_scanning or pause_both:
							print "API URL IS :"+str(api_url)
							content_status=Custom().getApiContent(proj_id,api_url,add_params,"post")
							if content_status["status"]=="success":
								content=content_status["value"]
								return JsonResponse({'project_id':proj_id,'error':'False','success':'True'})
							else:
								error_msg='Can not fetch Configuration '+str(content_status["value"])
								
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
				print "99"
				return JsonResponse({'project_id':proj_id,'error':'True','success':'False','error_msg':str(eex)})
			except Exception ,ex:
				return JsonResponse({'project_id':proj_id,'error':'True','success':'False','error_msg':str(ex)})

	
class Vul_Scan(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		try:
			print "Posted"
			#data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			th=request.POST["threading"];
			if th=="True":
				threading=True
			else:
				threading=False

			print "Obtained Project id :"+str(proj_id)
			error_msg=''
			if proj_id !=None:
				user_obj=Profile.objects.get(id=request.user.id)
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
				print "99"
				return render(request,"vul_scan.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101"
				return render(request,"vul_scan.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})

			




class Discovery(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get(self,request):
		try:
			proj_id=request.GET["proj_id"]
			proj_name=request.GET["proj_name"]
			in_prog='In Progress'
			if proj_id !=None and proj_name !=None:
				user_obj=Profile.objects.get(id=request.user.id)
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
								print "Obtained percentage is :"+str(percentage)
								#url_="details_update
								if percentage ==100:
									percentage=99
									#in_prog='complete'
								return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':in_prog,'percentage':str(percentage),'continue':'True'})
							else:
								return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'Can not fetch percentage '+str(percentage_status["value"]),'continue':'False'})

						elif discovery_status=="complete":
							percentage="100"
							in_prog="complete"
							return render(request,"details_update.html",{'project_id':proj_id,'project_name':proj_name,'project_status':in_prog,'percentage':str(100),'continue':'False'})
						else:
							percentage="0"
							in_prog="error"
							return render(request,"details.html",{'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':'Cant fetch project state','continue':'False'})
					else:
						return render(request,"details.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'Can not fetch project status '+str(resp_status["value"]),'continue':'False'})

				else:
						return render(request,"details.html",{'project_id':proj_id,'project_name':proj_name,'error':'True','project_status':'error','error_msg':'You do not have the ownership of the selected project ','continue':'False'})

			else:
						return render(request,"details.html",{'project_id':'','project_name':'','error':'True','project_status':'error','error_msg':'Either of Project id or Project_name not supplied with input ','continue':'False'})

		except Exception ,eex:
			try:
				return render(request,"details.html",{'project_id':proj_id,'project_name':proj_name,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				return render(request,"details.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})



class Config(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'
	
	def post(self,request):
		try:
			print "Posted"
			data=json.loads(request.POST["data"]);
			proj_id=request.POST["project_id"];
			print "Obtained Project id :"+str(proj_id)
			if proj_id !=None:
				user_obj=Profile.objects.get(id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						print "11"
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="complete" and vul_scan_status=="incomplete":
							print "22"
							content_status=Custom().getApiContent(proj_id,"/config/",{"data":data,"concurrent":"0","project_id":proj_id},"post")
							#print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nObtained Response is :"+str(content_status)
							if content_status["status"]=="success":
								content=content_status["data"]
								updated_svc_list=content_status["value"] #List of dict
								if content[0]["status"]=="success":
									data_=content[0]["value"]
									print "33"
									return render(request,"reconfigure_update.html",{'project_id':proj_id,'content':data_,'updated_svc_list':updated_svc_list,'continue':'True'})
								else:
									return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':content[0]["value"],'continue':'False','updated_svc':updated_svc_list})
							else:
								print "44"
								return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration '+str(content_status["value"]),'continue':'False'})
						else:
							print "55"
							return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch Configuration for the current project with its current status Discovery Status :'+discovery_status +' and Scanning status '+vul_scan_status,'continue':'False'})
	
					else:
						print "66"
						return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'Can not fetch project configuration '+str(resp_status["value"]),'continue':'False'})

				else:
						print "77"
						return render(request,"reconfigure_update.html",{'project_id':proj_id,'error':'True','project_status':'error','error_msg':'You do not have the ownership of the selected project ','continue':'False'})

			else:
						print "88"
						return render(request,"reconfigure_update.html",{'project_id':'','project_name':'','error':'True','project_status':'error','error_msg':'Project id not supplied with input ','continue':'False'})

		except Exception ,eex:
			try:
				print "99"
				return render(request,"reconfigure_update.html",{'project_id':proj_id,'project_status':'error','error':'True','error_msg':str(eex)})
			except Exception ,ex:
				print "101"
				return render(request,"reconfigure_update.html",{'project_id':'','project_name':'','project_status':'error','error':'True','error_msg':"No project Found--"+str(ex)})


	
	def get(self,request):
		try:
			proj_id=request.GET["proj_id"]
			#proj_name=request.GET["proj_name"]
			in_prog='In Progress'
			if proj_id and proj_id !=None :
				user_obj=Profile.objects.get(id=request.user.id)
				if Custom().getOwnership(proj_id,user_obj):
					resp_status=Custom().getApiContent(proj_id,"/project_status/")
					if resp_status["status"]=="success":
						stat_val=resp_status["value"]
						discovery_status=stat_val["project_status"]
						vul_scan_status=stat_val["project_exploits_status"]
						if discovery_status=="complete" and vul_scan_status=="incomplete":
							content_status=Custom().getApiContent(proj_id,"/config/")
							if content_status["status"]=="success":
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



class Scan(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def get_switches(self):	
		content_status=Custom().getApiContent(proj_id,"/config/")
		if content_status["status"]=="success":
			content=content_status["v"]
		switch_list=[]
		switch={}
		switch["id"]=0
		switch["name"]="test0"
		switch_list.append(switch)
		switch={}
		switch["id"]=1
		switch["name"]="test1"
		switch_list.append(switch)
		return switch_list 

	def get(self,request):
		return render(request,"scan.html",{'switches':self.get_switches()})

	#{"app_key":"","project_name":"","IP_range":"","Port_range":"","switch":"","assessment_id":""}'
	def post(self ,request):
		try:
			#print str(request.user)			
			#print str(request.user.id)
			api_address=Custom().get_api_address()
			form_attr=ScanAttributes(request.POST)
			if form_attr.is_valid():
				print "Form is valid !!!"
				ass_id=Custom().generate_uuid()
				user_obj=Profile.objects.get(id=request.user.id)
				Projects.objects.create(user=user_obj,project_id='',assessment_id=str(ass_id))				
				print "Created Assessment id successfully"
				url = api_address +"/scan/"
				api_key=getattr(settings,'API_KEY',None)
				app_id=getattr(settings,'APP_ID',None)
				
				data = {"app_key" : api_key,"project_name":form_attr.cleaned_data["Project_name"],
				"IP_range":form_attr.cleaned_data["Ip_range"],"Port_range":form_attr.cleaned_data["Port_range"],
				"switch":form_attr.cleaned_data["Switch"],"assessment_id":str(ass_id),"mode":form_attr.cleaned_data["Mode"],"app_id":str(app_id)}
				
				data_json = json.dumps(data)
				headers = {'Content-type': 'application/json'}
				response = requests.post(url, data=data_json, headers=headers)
				print "Response obtained is :"+str(response)	
				resp={}
				resp=json.loads(str(response.json()))	
				#print "Updated Json format is : "+str(resp)	
				if resp["status"]=="success":
					print "Success"
					project_obj=Projects.objects.get(user=user_obj,assessment_id=str(ass_id))
					project_obj.project_id=resp["value"]
					project_obj.save()
					return render(request,"details.html",{'project_id':resp["value"],'project_name':form_attr.cleaned_data["Project_name"],'project_status':'In Progress'})
				else:
					print "Failure"				
					return render(request,"scan.html",{'success':'False','error':resp["value"]})
			else:
				print "Inside errors !!"
				return render(request,"scan.html",{'success':'False','error':'Validation errors','form':form_attr,'switches':self.get_switches()})

		except Exception ,eex:
			print "Exception :"+str(eex)
			return render(request,"scan.html",{'success':'False','error':str(eex),'switches':self.get_switches()})




		
