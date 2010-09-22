
import re
from ctypes import *
from admin import *

class Kadm5:
	"""
	This class handles kadm5 client library.
	"""
	
	def __init__(self):
		self.codes = self.getDefined("/usr/include/kadm5/kadm_err.h")
		self.kadm = cdll.LoadLibrary('libkadm5clnt.so')
	
	def getDefined(self, filename):
		"""
		Reads error codes from filename and puts them to the dictionary
		"""
		codes = {}
		file = open(filename, 'r')
		for line in file:
			pattern = "(#define)\s+(\S+)\s+\((\S+)L\)"
			if re.match(pattern, line):
				out = re.match(pattern, line)
				codes[out.group(3)] = out.group(2)
		return codes
	
	def checkResult(self, result):
		"""
		Check the result returned by called libraries and print error if something went wrong
		"""
		if result != 0:
			c = str(result)
			print self.__class__.__name__ + ": " + self.codes.get(c, 'unknown')+" ("+c+")"
			return False
		return True

	def krb5_chpass_principal(self, pclient, ppassw, ppassw_new, prealm, pservice):
		"""
		Changes password for principal
		"""

		client = c_char_p(pclient)
		passw = c_char_p(ppassw)
		passw_new = c_char_p(ppassw_new)
		realm = c_char_p(prealm)
		service = c_char_p(pservice)
		db_args = c_char_p()
		server_h = c_void_p()

		# init context
		context = krb5_context()
		krb5_err = self.kadm.kadm5_init_krb5_context(byref(context))
		if not self.checkResult(krb5_err):
			return krb5_err

		# get config params
		params = kadm5_config_params()
		krb5_err = self.kadm.kadm5_get_config_params(
			context, c_int(0),
			byref(params), byref(params))
		if not self.checkResult(krb5_err):
			self.kadm.krb5_free_context(context)
			return krb5_err

		# init kadm
		krb5_err = self.kadm.kadm5_init(
			context, client,
			passw, service, 
			pointer(params), 
			krb5_ui_4(0x12345601), krb5_ui_4(0x12345702),
			pointer(db_args), pointer(server_h))
		if not self.checkResult(krb5_err):
			self.kadm.krb5_free_context(context)
			return krb5_err

		# get principal structure
		principal = krb5_principal()
		krb5_err = self.kadm.krb5_parse_name(
			context, 
			client, 
			pointer(principal))
		if not self.checkResult(krb5_err):
			self.kadm.krb5_free_context(context)
			return krb5_err

		# change password
		krb5_err = self.kadm.kadm5_chpass_principal(
			server_h,
			principal,
			passw_new)
		if not self.checkResult(krb5_err):
			self.kadm.krb5_free_context(context)
			return krb5_err

		# destroy context
		self.kadm.krb5_free_context(context)
		return 0

# for testing 
if __name__ == '__main__':
	client = "test@CDTEL.LOCAL"
	passw = "testovac9pass"
	passw_new = "dal39pass"
	realm = "CDTEL.LOCAL"
	service = "kadmin/cdtel00pceux509.uxkdc.cdtel.cz"

	pwc = Kadm5()
	pwc.krb5_chpass_principal(client, passw, passw_new, realm, service)

