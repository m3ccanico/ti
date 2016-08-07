import pprint
import hashlib

class Helper():
	@classmethod
	def prettyprint(cls, dict):
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(dict)

	@classmethod
	def md5(cls, filename):
		hash_md5 = hashlib.md5()
		with open(filename, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_md5.update(chunk)
		return hash_md5.hexdigest()

	@classmethod
	def sha256(cls, filename):
		hash_sha256 = hashlib.sha256()
		with open(filename, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_sha256.update(chunk)
		return hash_sha256.hexdigest()
