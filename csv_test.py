if 1:
    import csv
     
    from django.contrib.auth.models import User
	from log.models import *
    #from django.core.validators import email_re
     
   # from website.accounts.models import UserProfile
    from django.db import IntegrityError
     
    members = open('users.csv', "rU")
    data = csv.DictReader(members)
     
    default_password = ''
     
    for row in data:
      email = row['Email']
      password= str(row['ID'])+'_'+str(email)
      username=str(email)
      firstname=row['Name']
      #print password
      if 1:#email_re.match(email):
        tokens = email.split('@')
        #username = tokens[0]  
        try:
          a=11
          #print "Hurraaa : "+str(username) +str(email) +" " +str(password) +str(firstname)
          user = User.objects.create_user(username, email, password)
          user.is_staff = False
          user.first_name=tokens[0]
          user.save()
          print "saved"
          #profile = UserProfile(user_id=user.id)
          #profile.save()
        except IntegrityError:
          print username


