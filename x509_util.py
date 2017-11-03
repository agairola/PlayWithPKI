""" x509_util.py """
from OpenSSL.crypto import load_certificate, dump_certificate, dump_privatekey
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, TYPE_RSA, TYPE_DSA
from OpenSSL.crypto import PKey, PKCS12
from Crypto.Util.asn1 import DerSequence
from six import PY3 as _PY3
from base64 import b64encode
from binascii import unhexlify, hexlify
from cryptography.hazmat.bindings.openssl.binding import Binding
import logging,re,jinja2,bdblib
from config_parser import showTechParser
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
buf = logging.handlers.BufferingHandler(200)
logger.addHandler(buf)


class stpCertDecoder:
    def action(self, filename):
        result_to_return = []
        self.task_debugs = []

        try:
            show_tech = open(filename).read()
        except Exception:
            return result_to_return

        stp = showTechParser()
        result_to_return = stp.process_running_config(filename, show_tech.splitlines())

        return result_to_return

class Clone:

	def cloneBegin(self, pem_file,Basename='certificate',pkcs_passphrase = 'cisco123'):
		"""
		Creates a PKCS12 (private key + certificate) for a given certificate.
		The resulting PKCS12 is an exact replica of the input certificate,
		with the exception of the key. Useful for scenarios wherein you have to
		use a customer's identity certificate in lab, but do not have the private key.
		"""
		html, text = main(pem_file, pkcs_passphrase,Basename)
		template = jinja2.Template("""
			<figure>
				{% if errors %}
					<figcaption style="color:red"><b>Errors:</b></figcaption>
				{% endif %}
				<ul>
					{% for error in errors %}
						<li style="color:red">{{ error }}</li>
					{% endfor %}
				</ul>
			</figure>
			<p>{{ html }}</p>
			<figure>
				{% if text %}
					<figcaption>Base64 encoded PKCS12 (Passphrase: {{ password }}):</figcaption>
				{% endif %}
				<pre>{{ text }}</pre>
			</figure>
		""")
		result = bdblib.TaskResult()
		errors = [r.msg for r in buf.buffer if r.levelno >= 40]
		result.append(bdblib.HTML(template.render(errors=errors,
												  html=html,
												  text=text,
												  password=pkcs_passphrase
												  )
								  )
					  )
		return (html,text,pkcs_passphrase)

def main(input_cert_text, pkcs_passphrase,Basename='certificate'):
	html = ''
	text = ''
	
	
	if input_cert_text:
		input_data = input_cert_text
	else:
		logger.error('Need input_cert_text')
		return html, text
	
	base_name = Basename
	
	cert = load_x509(input_data)
	
	if cert == -1:
		return html, text
	
	open(base_name + '_original_x509.pem', 'w').write(dump_certificate(FILETYPE_PEM, cert))
	
	sig_algo = cert.get_signature_algorithm()
	logger.info('Signaure algorithm: ' + sig_algo)
	
	key = generate_key(cert, sig_algo)
	if key == -1:
		return html, text
	
	rc = sign_certificate(cert, key, sig_algo)
	if rc == -1:
		return html, text
	
	pkcs12, pkcs12_pem, privatekey_pem = generate_pkcs12(cert, key, pkcs_passphrase)
	x509_pem = dump_certificate(FILETYPE_PEM, cert)
	
	open(base_name + '_replica_p12.pem', 'w').write(pkcs12_pem)
	open(base_name + '_replica_p12.cer', 'wb').write(pkcs12)
	open(base_name + '_replica_key.pem', 'w').write(privatekey_pem)
	open(base_name + '_replica_x509.pem', 'w').write(x509_pem)
        certurl=base_name + '_replica_x509.pem'
        html = '<a target="_blank" href="https://scripts.cisco.com:443/ui/use/saurabhtry?certfile='+base_name+'_replica_x509.pem'+'&autorun=true&log=true">Edit the Cloned Certificate</a><br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/api/v1/files/' + base_name + '_replica_p12.pem">Download the new PKCS12 in PEM.</a>'
	html += ' (Passphrase: ' + pkcs_passphrase + ')<br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/api/v1/files/' + base_name + '_replica_p12.cer">Download the new PKCS12 in DER.</a>'
	html += ' (Passphrase: ' + pkcs_passphrase + ')<br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/api/v1/files/' + base_name + '_replica_key.pem">Download the new key in PEM.</a><br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/api/v1/files/' + base_name + '_replica_x509.pem">Download the new X509 certificate in PEM.</a><br />'
	html += '<br />'
	html += 'Compare the x509 decode of original and new certificate:<br />'
	html += '(Please report if you notice any differences)<br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/ui/use/standalone_cert_decoder?autorun=true&cert_file=' + base_name + '_original_x509.pem' + '">Original</a><br />'
	html += '<a target="_blank" href="https://scripts.cisco.com/ui/use/standalone_cert_decoder?autorun=true&cert_file=' + base_name + '_replica_x509.pem' + '">Replica</a><br />'
	text = pkcs12_pem
	return html, text

	
def load_x509(input_data):
	# TRY PEM first:
	try:
		cert = load_certificate(FILETYPE_PEM, input_data)
	except:
		logger.info('Input not in PEM')
	else:
		logger.info('Input is in PEM')
		return cert

	# Now try DER:
	try:
		cert = load_certificate(FILETYPE_ASN1, input_data)
	except:
		logger.info('Input not in DER')
	else:
		logger.info('Input is in DER')
		return cert
	
	# Now try hex:
	input_data = sanitize_hex_input(input_data)
	try:
		input_data = unhexlify(input_data)
	except TypeError as e:
		if 'Odd-length string' in e:
			logger.error('Input neither PEM nor DER. If you pasted the hex from a cisco running configuration, make sure you dont miss any character.')
		else:
			raise
	except:
		raise
	else:
		try:
			cert = load_certificate(FILETYPE_ASN1, input_data)
		except:
			logger.info('Input not hex too')
			logger.error('Couldnt load the certificate')
			raise
		else:
			logger.info('Input is in DER')
			return cert
	
	return -1

def sanitize_hex_input(h):
	lines = h.splitlines()
	s = ''
	for line in lines:
		if re.match(r'\s*[0-9A-Fa-f\s]*$', line, re.M):
			s += line
	s = re.sub(r'\s+', '', s)
	return s

def generate_key(cert, sig_algo):
	key_type = get_key_type(sig_algo)
	if key_type == TYPE_DSA or key_type == TYPE_RSA:
		key = create_integer_key(cert, key_type)
	elif key_type == 'ECDSA':
		key = create_elliptic_key(cert)
	else:
		return -1
	return key

def get_key_type(sig_algo):
	if re.search('ecdsa', sig_algo, re.I):
		key_type = 'ECDSA'
	elif re.search('dsa', sig_algo, re.I):
		key_type = TYPE_DSA
	elif re.search('rsa', sig_algo, re.I):
		key_type = TYPE_RSA
	else:
		key_type = -1
		logger.error('Unknown signature algorithm: ' + sig_algo)
	return key_type

def create_integer_key(cert, key_type):
	key_size = int(cert.get_pubkey().bits())
	logger.info('Key Size: ' + str(key_size))
	key = PKey()
	key.generate_key(key_type, key_size)
	return key

def create_elliptic_key(cert):
	curve_name = get_curve_name_from_cert(cert)
	if curve_name == -1:
		return -1
	key = EllipticCurvePKey()
	key.generate_ec_key(curve_name)
	return key


def get_curve_name_from_cert(cert):
	#https://tools.ietf.org/html/rfc5280#section-4.1
	cert_der = dump_certificate(FILETYPE_ASN1, cert)
	CurveObjectIdDer = get_curve_object_id_from_x509(cert_der)
	if hexlify(CurveObjectIdDer)[0:2] == '06':
		logger.info('EC param is an OID. Good to go.')
	elif hexlify(CurveObjectIdDer)[0:2] == '30':
		logger.error('Looks like the key in original certificate was encoded with "explicit" param_enc. '\
					 +'This is not supported yet. Using the default named_curve secp384r1.'\
					 +'Do send a feedback if you would like this feature implemented.')
		return str('secp384r1')
	else:
		logger.error('EC param neither OID, nor SEQUENCE. Rasing error so that I get notified.')
		raise
	
	curve_name = openssl_shim_object_data_to_name(CurveObjectIdDer)
	return curve_name

def get_curve_object_id_from_x509(cert_der):
	TBSCertificate = decode_der_sequence(cert_der, 0)
	SubjectPublicKeyInfo = decode_der_sequence(TBSCertificate, 6)
	AlgorithmIdentifier = decode_der_sequence(SubjectPublicKeyInfo, 0)
	CurveObjectIdDer = decode_der_sequence(AlgorithmIdentifier, 1)
	return CurveObjectIdDer

def decode_der_sequence(data, seq):
	der = DerSequence()
	der.decode(data)
	ret = der._seq[seq]
	return ret

def openssl_shim_object_data_to_name(oid_der):
	o = _ffi.new('ASN1_OBJECT **')
	opp = _ffi.new('unsigned char **', _ffi.new('unsigned char[]', oid_der))
	obj = _lib.d2i_ASN1_OBJECT(o, opp, len(oid_der))
	nid = _lib.OBJ_obj2nid(obj)
	ln = _lib.OBJ_nid2ln(nid)
	long_name = _ffi.string(ln)
	logger.info('Curve NID: ' + str(nid))
	logger.info('Curve Name: ' + long_name)
	if long_name == 'undefined':
		logger.error('Couldnt decode the named_curve from the original certificate. Using default secp384r1')
		return str('secp384r1')
	return long_name

def sign_certificate(cert, key, sig_algo):
	cert.set_pubkey(key)
	sig_algo = sanitize_sig_algorithm(sig_algo) # See comments in the function
	try:
		cert.sign(key, str(sig_algo))
	except ValueError as e:
		if 'No such digest method' in e:
			logger.error('The signature algorithm is not yet supported: ' + sig_algo)
			return -1
		else:
			raise
	except:
		raise
	return 1
def sanitize_sig_algorithm(sig_algo):
	# Sometimes, openssl doesn't accept some strings in X509_sign for signature algorithm,
	# even though, it prints the these same strings in asn1_parse and X509_print.
	# Examples, ecdsa-with-SHA1 works and but ecdsa-with-SHA512 doesn't. Instead using SHA512 works correctly.
	# This has nothing to do with long_name or short_name. May be some names are not present in OBJ_NAME_TYPE_MD_METH
	# Need more investigation as to whether this is a bug or expected.
	# For now, this function will deal with such cases as and when they are found.
	
	# Remove 'ecdsa-with-' from the string. Results are tested to be correct.
	sig_algo = sig_algo.replace('ecdsa-with-', '')
	
	return sig_algo


def generate_pkcs12(cert, key, pkcs_passphrase):
	p12 = PKCS12()
	p12.set_privatekey(key)
	p12.set_certificate(cert)
	pkcs12 = p12.export(passphrase=pkcs_passphrase)
	p12_b64 = b64encode(pkcs12)
	lines = []
	for i in xrange(0, len(p12_b64), 64):
		lines.append(p12_b64[i:i+64])
	pkcs12_pem = '-----BEGIN PKCS12-----\n' + '\n'.join(lines) + '\n-----END PKCS12-----'
	privatekey_pem = dump_privatekey(FILETYPE_PEM, p12.get_privatekey())
	return pkcs12, pkcs12_pem, privatekey_pem

'''The code below is taken from an unmerged pull req (as of pyOpenSSL 15.1)
https://github.com/pyca/pyopenssl/pull/308
'''
class EllipticCurvePKey(PKey):

	def generate_ec_key(self, curve_name):
		"""
		Generate an ec key with the given curve name.

		This generated a key "into" the this object.

		:param curve_name: The name of the elliptic curve to use.
		:type curve_name: :class:`str`
		:raises TypeError: If curve_name is not a string.
		:raises ValueError: If curve_name is not a supported
			curve name.
		"""
		if not isinstance(curve_name, str):
			raise TypeError("curve_name must be a string")

		curve = get_elliptic_curve(curve_name)
		ec = curve._to_EC_KEY()

		if not _lib.EC_KEY_generate_key(ec):
			# TODO: This is untested.
			_raise_current_error()
		if not _lib.EVP_PKEY_set1_EC_KEY(self._pkey, ec):
			# TODO: This is untested.
			_raise_current_error()

		self._initialized = True


class _EllipticCurve(object):
	"""
	A representation of a supported elliptic curve.

	@cvar _curves: :py:obj:`None` until an attempt is made to load the curves.
		Thereafter, a :py:type:`set` containing :py:type:`_EllipticCurve`
		instances each of which represents one curve supported by the system.
	@type _curves: :py:type:`NoneType` or :py:type:`set`
	"""
	_curves = None

	if _PY3:
		# This only necessary on Python 3.  Morever, it is broken on Python 2.
		def __ne__(self, other):
			"""
			Implement cooperation with the right-hand side argument of ``!=``.

			Python 3 seems to have dropped this cooperation in this very narrow
			circumstance.
			"""
			if isinstance(other, _EllipticCurve):
				return super(_EllipticCurve, self).__ne__(other)
			return NotImplemented

	@classmethod
	def _load_elliptic_curves(cls, lib):
		"""
		Get the curves supported by OpenSSL.

		:param lib: The OpenSSL library binding object.

		:return: A :py:type:`set` of ``cls`` instances giving the names of the
			elliptic curves the underlying library supports.
		"""
		if lib.Cryptography_HAS_EC:
			num_curves = lib.EC_get_builtin_curves(_ffi.NULL, 0)
			builtin_curves = _ffi.new('EC_builtin_curve[]', num_curves)
			# The return value on this call should be num_curves again.  We
			# could check it to make sure but if it *isn't* then.. what could
			# we do? Abort the whole process, I suppose...?  -exarkun
			lib.EC_get_builtin_curves(builtin_curves, num_curves)
			return set(
				cls.from_nid(lib, c.nid)
				for c in builtin_curves)
		return set()

	@classmethod
	def _get_elliptic_curves(cls, lib):
		"""
		Get, cache, and return the curves supported by OpenSSL.

		:param lib: The OpenSSL library binding object.

		:return: A :py:type:`set` of ``cls`` instances giving the names of the
			elliptic curves the underlying library supports.
		"""
		if cls._curves is None:
			cls._curves = cls._load_elliptic_curves(lib)
		return cls._curves

	@classmethod
	def from_nid(cls, lib, nid):
		"""
		Instantiate a new :py:class:`_EllipticCurve` associated with the given
		OpenSSL NID.

		:param lib: The OpenSSL library binding object.

		:param nid: The OpenSSL NID the resulting curve object will represent.
			This must be a curve NID (and not, for example, a hash NID) or
			subsequent operations will fail in unpredictable ways.
		:type nid: :py:class:`int`

		:return: The curve object.
		"""
		return cls(lib, nid, _ffi.string(lib.OBJ_nid2sn(nid)).decode("ascii"))

	def __init__(self, lib, nid, name):
		"""
		:param _lib: The :py:mod:`cryptography` binding instance used to
			interface with OpenSSL.

		:param _nid: The OpenSSL NID identifying the curve this object
			represents.
		:type _nid: :py:class:`int`

		:param name: The OpenSSL short name identifying the curve this object
			represents.
		:type name: :py:class:`unicode`
		"""
		self._lib = lib
		self._nid = nid
		self.name = name

	def __repr__(self):
		return "<Curve %r>" % (self.name,)

	def _to_EC_KEY(self):
		"""
		Create a new OpenSSL EC_KEY structure initialized to use this curve.

		The structure is automatically garbage collected when the Python object
		is garbage collected.
		"""
		key = _lib.EC_KEY_new()
		group = _lib.EC_GROUP_new_by_curve_name(self._nid)
		_lib.EC_GROUP_set_asn1_flag(group, _lib.OPENSSL_EC_NAMED_CURVE)
		_lib.EC_KEY_set_group(key, group)
		_lib.EC_GROUP_free(group)
		return _ffi.gc(key, _lib.EC_KEY_free)


def get_elliptic_curves():
	"""
	Return a set of objects representing the elliptic curves supported in the
	OpenSSL build in use.

	The curve objects have a :py:class:`unicode` ``name`` attribute by which
	they identify themselves.

	The curve objects are useful as values for the argument accepted by
	:py:meth:`Context.set_tmp_ecdh` to specify which elliptical curve should be
	used for ECDHE key exchange.
	"""
	return _EllipticCurve._get_elliptic_curves(_lib)


def get_elliptic_curve(name):
	"""
	Return a single curve object selected by name.

	See :py:func:`get_elliptic_curves` for information about curve objects.

	:param name: The OpenSSL short name identifying the curve object to
		retrieve.
	:type name: :py:class:`unicode`

	If the named curve is not supported then :py:class:`ValueError` is raised.
	"""
	for curve in get_elliptic_curves():
		if curve.name == name:
			return curve
	raise ValueError("unknown curve name", name)