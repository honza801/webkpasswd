"""
WebKpasswd

Changes kerberos password via web interface.

The application is supposed to run on cherrypy+genshi stack.
"""

# Import CherryPy global namespace
import cherrypy
from genshi.template import TemplateLoader
import string
import re
import logging
import subprocess
from kadm import *

class WebKpasswd:
	""" 
	Root request handler class. 
	"""

	def __init__(self):
		self.prefix = "/"
		# default realm
		self.realm = "CDTEL.LOCAL"
		self.page_title = "kpasswd form!"
		
		self.messages = {
			'notchanged' : { 
				'text' : "Error, password not chaged!",
				'type' : "redmessage"
			},
			'nomatch' : {
				'text' : "New passwords do not match!",
				'type' : "redmessage"
			},
			'princerror' : {
				'text' : "Principal invalid!",
				'type' : "redmessage"
			},
			'realmerror' : {
				'text' : "Realm invalid!",
				'type' : "redmessage"
			},
			'newpassshort' : {
				'text' : "New password is too short!",
				'type' : "redmessage"
			},
			'newpassinv' : {
				'text' : "New password is invalid!",
				'type' : "redmessage"
			},
			'success' : {
				'text' : "Password changed sucessfully.",
				'type' : "greenmessage"
			},
		}

		self.logger = logging.getLogger(self.__class__.__name__)
		self.logger.setLevel(logging.INFO)
		ch = logging.StreamHandler()
		ch.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
		self.logger.addHandler(ch)

	def kpasswd(self, message="none", *another):
		"""
		WebKpasswd form renderer
		"""
		genshiparams = {
			'title' : self.page_title,
			'message' : self.messages.get(message,''),
			'realm' : self.realm,
		}
		return loader.load('kpasswd.html').generate(genparams=genshiparams).render('html', doctype='html')

	def kpasswdf(self, 
		principal="princ0", 
		password="pass0", 
		newpass="newpass", newpassv="notthesamepass", 
		*another):
		
		"""
		Main algorithm for changing password.
		It also does some input checking.
		"""
		if cherrypy.request.method == 'POST':
			# check input
			if len(principal) < 1:
				self.raise_message(principal, "princerror")

			if not newpass == newpassv:
				self.raise_message(principal, "nomatch")
			if len(newpass) < 3:
				self.raise_message(principal, "newpassshort")
			
			if len(principal.split("@")) < 2:
				trealm = self.realm
				principal += "@"+trealm
			else:
				trealm = principal.split("@")[1]
			if  len(trealm) < 1:
				self.raise_message(principal, "realmerror", trealm)

			# call C binaries
			kadm = Kadm5()
			ret = kadm.krb5_chpass_principal(
				principal, 
				password, newpass, 
				trealm, "kadmin/cdtel00pceux509.uxkdc.cdtel.cz")
			
			# check the result
			if ret > 0:
				self.raise_message(principal, "notchanged", trealm)
			else:
				self.raise_message(principal, "success", trealm)
		# if there is no POST, return to main page
		raise cherrypy.HTTPRedirect(self.prefix+"kpasswd")

	kpasswd.exposed = True
	kpasswdf.exposed = True

	def default(self, *another):
		"""
		This method redirects all the 'unknown' requests to the /kpasswd
		"""
		raise cherrypy.HTTPRedirect(self.prefix+"kpasswd")
	
	default.exposed = True
	
	def raise_message(self, principal, message, realm=""):
		"""
		Logs message to the console and redirects to the main page with message
		"""
		if realm:
			self.logger.info(self.messages.get(message)['text']+" principal:"+principal+", realm:"+realm)
			raise cherrypy.HTTPRedirect(self.prefix+"kpasswd?message="+message)
		else:
			self.logger.info(self.messages.get(message)['text']+" principal:"+principal)
			raise cherrypy.HTTPRedirect(self.prefix+"kpasswd?message="+message)


import os.path
current_dir = os.path.dirname(__file__)
kdcconf = os.path.join(current_dir, 'webkpasswd.conf')
loader = TemplateLoader('templates', auto_reload=True)

if __name__ == '__main__':
    cherrypy.quickstart(WebKpasswd(), config=kdcconf)
else:
    # This branch is for the test suite; you can ignore it.
    cherrypy.tree.mount(WebKpasswd(), config=kdcconf)

