#!python
#log/views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from random import randint

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.db.models.query_utils import Q
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from email_config import DEFAULT_FROM_EMAIL
from django.views.generic import *
from log.forms import PasswordResetRequestForm, SetPasswordForm
from django.contrib import messages
from django.contrib.auth.models import User



# Create your views here.
# this login required decorator is to not allow to any  
# view without authenticating

def custom(index):
	sarcasm=[]
	#print "INdex is :"+str(index)
	sarcasm.append("You go girl! And don't come back.(Ask yourself !! Why would i keep it there)")
	sarcasm.append("You go girl! And don't come back.(Lol PenTester)")
	sarcasm.append("Lol are you kidding me !!! Seriously R U !")
	sarcasm.append("And You want an apraisal .Claps for you IQ")
	sarcasm.append("If i wanted to kill myself i would climb your self-confidance and jump to your IQ")
	sarcasm.append("I never forget a face, but in your case I'll be glad to make an exception.")
	sarcasm.append("Tell me... Is being stupid a profession or are you just gifted?")
	sarcasm.append("This is why some people appear bright until they act")
	sarcasm.append("U think i am stupid.Go and do some pen testing ,u might actually find some passwords")
	sarcasm.append("Before addressing artificial intellegence ,why dont we do something about natural stupidity.")
	sarcasm.append("I dont even want to waste a quote on u")
	return sarcasm[index]

@login_required(login_url="login/")
def home(request):
	random_=randint(1,10)
	
	return render(request,"home.html",{"image":str(random_),"sarcasm":custom(random_)})



class change_password(LoginRequiredMixin,View):
	login_url='/login/'
	redirect_field_name='next'

	def post(self,request):
		if 1:#equest.method == 'POST':
		    form = PasswordChangeForm(request.user, request.POST)
		    #print str(form)
		    if form.is_valid():
		       # print "Form is valid :"
		        user = form.save()
		        update_session_auth_hash(request, user)  # Important!
		        messages.success(request, 'Your password was successfully updated!')
		       # print "Returning success"
		        return render(request, 'change_password.html', {
		    'success': 'True',
			'success_msg':'Your password was successfully updated!'
		
		})
		    else:
		        messages.error(request, 'Please correct the error below.')
		else:
		    print "Inside else and returning "
		    form = PasswordChangeForm(request.user)
		return render(request, 'change_password.html', {
		    'form': form
		})

	def get(self ,request):
		form = PasswordChangeForm(request.user)
		return render(request, 'change_password.html', {
		    'form': form
		})



class ResetPasswordRequestView(FormView):
    # code for template is given below the view's code
    template_name = "account/test_template.html"
    success_url = '/login/'
    form_class = PasswordResetRequestForm

    @staticmethod
    def validate_email_address(email):

        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def reset_password(self, user, request):
        print "User is :"+str(user)
        print "without str rep -user is :" 
        print user
        print "PK IS : "+str(user.pk)
        print "forced byte is : "+str(force_bytes(user.pk))
        print "Now encoded data is :"+str(urlsafe_base64_encode(force_bytes(user.pk)))
        print "Again :"+str(urlsafe_base64_encode('58'))
        c = {
            'email': user.email,
            'domain': request.META['HTTP_HOST'],
            'site_name': 'www.paladion.net',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }
        subject_template_name = 'registration/password_reset_subject.txt'
        # copied from
        # django/contrib/admin/templates/registration/password_reset_subject.txt
        # to templates directory
        email_template_name = 'registration/password_reset_email.html'
        # copied from
        # django/contrib/admin/templates/registration/password_reset_email.html
        # to templates directory
        subject = loader.render_to_string(subject_template_name, c)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        email = loader.render_to_string(email_template_name, c)
        send_mail(subject, email, DEFAULT_FROM_EMAIL,
                  [user.email], fail_silently=False)
        print "Mail sent hurraa"		

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        try:
            if form.is_valid():
                data = form.cleaned_data["email_or_username"]
            # uses the method written above
            if self.validate_email_address(data) is True:
                '''
                If the input is an valid email address, then the following code will lookup for users associated with that email address. If found then an email will be sent to the address, else an error message will be printed on the screen.
                '''
                associated_users = User.objects.filter(
                    Q(email=data))
                print str(associated_users)
                if associated_users.exists():
                    for user in associated_users:
                        self.reset_password(user, request)

                    result = self.form_valid(form)
                    messages.success(
                        request, 'An email has been sent to {0}. Please check its inbox to continue reseting password.'.format(data))
                    return result
                result = self.form_invalid(form)
                messages.error(
                    request, 'No user is associated with this email address')
                return result
            
            messages.error(request, 'Invalid Input')
        except Exception as e:
             print(e)
        return self.form_invalid(form)


class PasswordResetConfirmView(FormView):
    template_name = "account/test_template.html"
    success_url = '/login/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            print "Exception caught !!!"
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password = form.cleaned_data['new_password2']
                if len(new_password) < 8:
                    messages.error(
                    request, 'Password reset has not been unsuccessful .Minimum length required for password is 8')
                    return self.form_invalid(form)

                user.set_password(new_password)
                user.save()
                #print "Saved changes !!!"
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(
                    request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(
                request, 'The reset password link is no longer valid.')
            return self.form_invalid(form)
