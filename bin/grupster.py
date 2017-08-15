"""
 The grupster module for gruppy
"""
import sqlite3
import yaml
import logging
import os
import sys
import tempfile

APPNAME = 'gruppy'
PROGNAME = '%s' % (APPNAME) # synonym
VERSION = '0.1.3'
PIDFILE = '/var/run/%s.pid' % (APPNAME)
CFGFILE = '/etc/%s/%s.yml' % (APPNAME,APPNAME)

# feed type constants
FT_UNKNOWN = 0
FT_FILESYSTEM = 1
FT_S3_VIA_AWSCLI = 2
FT_S3_AWS_GZJSON = 3

FILTER_TYPE_UNKNOWN = 0
FILTER_TYPE_GREP = 1
FILTER_TYPE_SED = 2

logger = None

def convert_loglevstr_to_loglevint(loglevstr):
	""" returns logging.NOTSET if we fail to match string """

	if loglevstr.lower() == "critical":
		return logging.CRITICAL
	if loglevstr.lower() == "error":
		return logging.ERROR
	if loglevstr.lower() == "warning":
		return logging.WARNING
	if loglevstr.lower() == "info":
		return logging.INFO
	if loglevstr.lower() == "debug":
		return logging.DEBUG
	return logging.NOTSET

def convert_loglevint_to_loglevstr(loglevint):
	""" if no match, returns None """

	if loglevint == logging.CRITICAL:
		return "critical"
	if loglevint == logging.ERROR:
		return "error"
	if loglevint == logging.WARNING:
		return "warning"
	if loglevint == logging.INFO:
		return "info"
	if loglevint == logging.DEBUG:
		return "debug"
	if loglevint == logging.NOTSET:
		return "notset"
	return None

class GruppyConfig(object):
	"""
	 A GruppyConfig object

	 Attributes:
	  database.filespec 
	  logging.directory 
	  logging.filespec 
	  logging.level
	  logstash.program 
	  tempdir
	"""
	def __init__(self):

		self.dbfilespec = '/var/lib/%s/%s.db' % (PROGNAME,PROGNAME)
		self.logdir = '/var/log/%s' % (PROGNAME)
		self.logfile = '%s/%s.log' % (self.logdir,PROGNAME)
		self.loglevel = logging.INFO
		self.logstashbin = '/usr/share/logstash/bin/logstash'
		# create temporary directory used by this process
		if os.path.isdir('/dev/shm'):
			self.tempdir = tempfile.mkdtemp(dir='/dev/shm')
		else:
			self.tempdir = tempfile.mkdtemp()

		config_read_succeeded = False
		try:
			with open(CFGFILE,'r') as f:
				cfg_file_data = yaml.safe_load(f)
				config_read_succeeded = True
		except Exception, e:
			msg = "unable to read configfile {%s}, proceeding with defaults: %s\n" \
				 % (CFGFILE,str(e))
			warnings.warn(msg)
			pass

		if config_read_succeeded == True and not cfg_file_data == None:
			if 'database.filespec' in cfg_file_data:
				self.dbfilespec = cfg_file_data['database.filespec']
			if 'logging.directory' in cfg_file_data:
				self.logdir = cfg_file_data['logging.directory']

			""" revoking ability to configure logfile """
			#if 'logging.filespec' in cfg_file_data:
			#	cfg.logfile = cfg_file_data['logging.filespec']

			if 'logging.level' in cfg_file_data:
				""" set cfg.loglevel to constant int value """
				retval = convert_loglevstr_to_loglevint(cfg_file_data['logging.level'])
				if not retval == logging.NOTSET:
					self.loglevel = retval
			if 'logstash.program' in cfg_file_data:
				self.logstashbin = cfg_file_data['logstash.program']

		return


	def __repr__(self):
		return """
<%s:
 %-20s: %s
 %-20s: %s
 %-20s: %s
 %-20s: %d
 %-20s: %s
>""" % ("GruppyConfig",
	"dbfilespec", self.dbfilespec,
	"logdir", self.logdir,
	"logfile", self.logfile,
	"loglevel", self.loglevel,
	"logstash program", self.logstashbin)


class FSPath(object):
	"""
	A FSPath object

	Attributes:
	 path 
	 feed_name
	 pattern
	"""
	def __init__(self,path,feed_name,pattern):

		self.path_template = path
		self.feed_name = feed_name
		if pattern == None:
			self.pattern = '*'
		else:
			self.pattern = pattern

	def __repr__(self):
		return """
<%s:
 %-20s: %s
 %-20s: %s
 %-20s: %r
>""" % ("FSPath","path_template",self.path_template,"feed_name",self.feed_name,"pattern",self.pattern)

	def find_files(self):
		"""
		Return a list of files found under path that match self.pattern,
		where path is obtained through parameter substitution from self.path_template
		"""

		path = ''
		if '$' in self.path_template:

			# perform template parameter substitution on path
			t = Template(self.path_template)
			path = t.substitute(THIS_YEAR = datetime.now().year, 
				THIS_MONTH = '%02d' % (datetime.now().month), 
				THIS_DATE = '%02d' % (datetime.now().day))

		else:
			path = self.path_template

		msg = "seeking files in path %s" % (path)
		logger.info(msg)
		#print "seeking files in path %s" % (path)
		# first, verify that path exists
		matches = []
		for root, dirnames, filenames in os.walk(path):
			for filename in fnmatch.filter(filenames, self.pattern):
				logger.debug("joining root (%s) to fname (%s)" % (root,filename))
				matches.append(os.path.join(root, filename))

		files_sorted_by_ctime = sorted(matches, key=os.path.getctime)
		return files_sorted_by_ctime

	def find_files_on_s3_via_awscli(self):
		"""
		Find files on s3 in target directory by calling 'aws s3 ls <path>'
		where path is obtained through parameter substitution from self.path_template
		e.b. 
		aws s3 ls s3://hap-log-qa/hap-qa-cloudtrail/AWSLogs/011448383031/CloudTrail/us-east-1/2017/06/12/
		"""
		path = ''
		if '$' in self.path_template:

			# perform template parameter substitution on path
			t = Template(self.path_template)
			path = t.substitute(THIS_YEAR = datetime.now().year, 
				THIS_MONTH = '%02d' % (datetime.now().month), 
				THIS_DATE = '%02d' % (datetime.now().day))

		else:
			path = self.path_template

		msg = "seeking files in path %s" % (path)
		logger.info(msg)
		# assert that aws is found at /root/.local/bin/aws
		cmd = "%s s3 ls s3:/%s/" % (AWSBIN, path)
		logger.info("cmd used to retrieve s3 filelist via awscli: %s" % (cmd))
		try:
			process = Popen(shlex.split(cmd), stdout=PIPE)
			(output, err) = process.communicate()
			exit_code = process.wait()
		except Exception, e:
			msg = "failed to retrieve s3 filelist via awscli: %s" % (str(e))
			logger.error(msg)
			return None

		# otherwise output contains a string, split into list of lines
		lines = output.splitlines()
		# but we only care about filenames, which are final element of multicolumn line
		filepaths = []
		# columns are date, time, size, filename
		# skip files that don't match current year and month
		pattern = re.compile('^%04d-%02d.*' % (datetime.now().year,datetime.now().month))
		for line in lines:
			filename = line.split()[3]
			if (pattern.match(filename)):
				filepaths.append("%s/%s" % (path,filename))

		return filepaths

class FeedFilter(object):
	"""
	A FeedFilter object

	Attributes:
	 name - string
	 filter_type - integer
	 negate - boolean
	 pattern - string
	 feed_name - string
	 enabled - boolean
	"""
	def __init__(self,name,filter_type,negate,pattern,feed_name,enabled):

		self.name = name
		self.filter_type = filter_type
		self.negate = negate
		self.pattern = pattern
		self.feed_name = feed_name
		self.enabled = enabled

	def __repr__(self):

		if self.negate == False:
			negate_me = "False"
		else:
			negate_me = "True"
		if self.enabled == False:
			enable_me = "False"
		else:
			enable_me = "True"
		return """
<%s:
 %-20s: %s
 %-20s: %s
 %-20s: %s
 %-20s: %s
 %-20s: %s
 %-20s: %s
>""" % (
	"FeedFilter",
	"name",self.name,
	"filter type",self.filter_type,
	"pattern",self.pattern,
	"feed name",self.feed_name,
	"negate?",negate_me,
	"enabled?",enable_me)		

class Feed(object):
	"""
	A Logstash input feed

	Attributes:
	 id - integer
	 name - text
	 type - integer (see the FT_<type> feed type constants!)
	 cfgfile - filespec of this feed's logstash config file
	 enabled - 0 (false) or 1 (true)
	 transform - 0 (false) or 1 (true)
	 transformation
	 convert_slow_query_format - 0 (false) or 1 (true)

	 Note: transformation is defined as an external command, script or program that 
	 would be run with the data file as sole argument. 

	 How transformations work is that ordinarily, input feed processes input file in place.
	 When tranform == True, though, we copy input file to temp directory,
	 apply the transformation, then input using the tranformed copy.
	"""
	def __init__(self,name,feedtype,filespec,enabled,transform,transformation,convert_slow_query_format):
	#def __init__(self,name,feedtype,filespec,enabled,transform,transformation):
		"""initialize the object"""

		self.name = name
		self.type = int(feedtype)
		self.cfgfile = filespec
		self.enabled = False # disabled by default
		if enabled == 0:
			self.enabled = False
		elif enabled == 1:
			self.enabled = True
		else:
			raise Exception('Feed init received invalid value for "enabled" attribute')
		self.transform = False
		if transform == 1:
			self.transform = True
		self.transformation = transformation
		self.convert_slow_query_format = False
		if convert_slow_query_format == 1:
			self.convert_slow_query_format = True
		self.filters = []

	def __repr__(self):
		ftstr = ''
		if self.type == FT_UNKNOWN:
			ftstr = "unknown"
		elif self.type == FT_FILESYSTEM:
			ftstr = "filesystem"
		elif self.type == FT_S3_VIA_AWSCLI:
			ftstr = "s3-via-awscli"
		elif self.type == FT_S3_AWS_GZJSON:
			ftstr = "s3-gz-aws-json2kv"
		else:
			raise Exception("invalid feed type contant value: %s" % (self.type))

		#slow_query_string = "False"
		#if self.convert_slow_query_format == True:
		#	slow_query_string = "True"

		return """
<%s:
 %-40s: %s
 %-40s: %s
 %-40s: %s
 %-40s: %r
 %-40s: %s
 %-40s: %r
 %-40s: %s
>""" % ("Feed","name",self.name,"type", ftstr,"cfgfile",self.cfgfile,"enabled?",
	self.enabled,"convert_slow_query_format?",self.convert_slow_query_format,"transform?",self.transform,"transformation",self.transformation)

	def is_valid_config_file(self):
		""" verify that self.cfgfile is a valid logstash config file """

		msg = "checking to see if %s has a valid config file, please wait ... " % (self.name)
		logger.info(msg)
		#sys.stdout.write("checking to see if %s has a valid config file, please wait ... " % (self.name))
		#sys.stdout.flush()
		#/usr/share/logstash/bin/logstash --path.settings /etc/logstash -f /usr/share/logstash/conf/elb-consolidated-logstash.conf -t
		
		logger.debug('%s --path.settings /etc/logstash -f %s -t' % (cfg['logstashbin'],self.cfgfile))
		cmd = '%s --path.settings /etc/logstash --path.data %s -f %s -t' % (cfg['logstashbin'],cfg['tempdir'],self.cfgfile)
		process = Popen(shlex.split(cmd), stdout=PIPE)
		process.communicate()
		exit_code = process.wait()
		# send newline
		#print
		if exit_code != 0:
			msg = "invalid config"
			logger.error(msg)
			#print "invalid config"
			return False

		msg = "config ok"
		logger.info(msg)
		#print "config ok"
		return True

	def fetch_interesting_paths(self,cfg):
		""" fetch interesting paths from the database """

		logger.info("fetching interesting paths for feed %s" % (self.name))

		try:
			conn = sqlite3.connect(cfg.dbfilespec)
		except Exception, e:
			msg = "Connect fail for db %s: %s" % (cfg.dbfilespec,str(e))
			logger.error(msg)
			return None

		c = conn.cursor()

		# get list of feeds and their properties
		query_get_interesting_paths = "SELECT * FROM interesting_paths WHERE feed_name = '%s'" % (self.name)
		try:
			c.execute(query_get_interesting_paths)
		except Exception, e:
			msg = "Execute fail on db %s for query %s: %s" \
			     % (cfg.dbfilespec,query_get_interesting_paths,str(e))
			logger.error(msg)
			conn.close()
			return None

		# fetchall returns a list of tuples
		rows = []
		try:
			rows = c.fetchall()
		except Exception, e:
			msg = "Fetchall fail on db %s for query %s: %s" \
			    % (cfg.dbfilespec,query_get_interesting_paths,str(e))
			logger.error(msg)
			conn.close()
			return None

		interesting_paths = []
		for r in rows:
			arglist = list(r)
			interesting_paths.append(FSPath(*arglist))

		conn.close()

		return interesting_paths

	def fetch_filters(self,cfg):
		""" return a dictionary of filters in which key is the filter name """
		try:
			conn = sqlite3.connect(cfg.dbfilespec)
		except Exception, e:
			print "Connect fail for db %s: %s" % (cfg.dbfilespec,str(e))
			return None
		c = conn.cursor()
		sql = "SELECT f.name,f.filter_type,f.negate,f.pattern,x.feed_name,x.enabled FROM feed_x_filter AS x,filters AS f WHERE x.feed_name = '%s' and x.filter_name = f.name" % (self.name)
		try:
			c.execute(sql)
		except Exception, e:
			print "Execute fail on db %s for query %s: %s" % (cfg.dbfilespec,sql,str(e))
			conn.close()
			return None
		# fetchall returns a list of tuples
		rows = []
		try:
			rows = c.fetchall()
		except Exception, e:
			print "Fetchall fail on db %s for query %s: %s" % (cfg.dbfilespec,query_get_feeds,str(e))
			conn.close()
			return None

		filters = {}
		for r in rows:
			filter_name = r[0]
			arglist = list(r)
			filters[filter_name] = FeedFilter(*arglist)
		conn.close()
		logger.debug(filters)
		self.filters = filters
		return filters

def init_logging(cfg):

	global logger

	# if main logfile doesn't exist, create it
	logdir = os.path.dirname(cfg.logfile)
	if not os.path.isdir(logdir):
		try:
			os.mkdir(logdir)
		except Exception, e:
			msg = "unable to create logdir: %s" % (str(e))
			print "%s" % (msg)

	if not os.path.isfile(cfg.logfile):
		try:
			with open(cfg.logfile, 'a'):
				os.utime(cfg.logfile, None)
		except Exception, e:
			msg = "unable to create logfile {%s}: %s" % (cfg.logfile,str(e))
			# can't log the error! should print this to stderr
			print "%s" % (msg)

	# logfile = '/var/log/fetch_%s_data.log' % (feed.name)
	logger = logging.getLogger(__name__)
	logger.setLevel(cfg.loglevel)
	# create file handler for logging
	handler = logging.FileHandler(cfg.logfile)
	handler.setLevel(cfg.loglevel)
	# create a logging format
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	# add the handler to the logger
	logger.addHandler(handler)
	print "Logging to %s" % (cfg.logfile)
	logger.info("starting")
	retval = convert_loglevint_to_loglevstr(logging.getLogger().getEffectiveLevel())
	if not retval == None:
		logger.info("log level: %s" % (retval))
	else:
		logger.info("log level: unknown")

	return

# argument is a GruppyConfig object
def fetch_feeds(cfg):
	""" return a dictionary of feeds in which key is feed name """

	try:
		conn = sqlite3.connect(cfg.dbfilespec)
	except Exception, e:
		print "Connect fail for db %s: %s" % (cfg.dbfilespec,str(e))
		return None

	c = conn.cursor()

	# get list of feeds and their properties
	query_get_feeds = 'SELECT * FROM feeds'
	try:
		c.execute(query_get_feeds)
	except Exception, e:
		print "Execute fail on db %s for query %s: %s" \
		 % (cfg.dbfilespec,query_get_feeds,str(e))
		conn.close()
		return None

	# fetchall returns a list of tuples
	rows = []
	try:
		rows = c.fetchall()
	except Exception, e:
		print "Fetchall fail on db %s for query %s: %s" \
		% (cfg.dbfilespec,query_get_feeds,str(e))
		conn.close()
		return None

	feeds = {}
	for r in rows:
		# name is the first element in tuple
		feed_name = r[0]
		arglist = list(r)
		feeds[feed_name] = Feed(*arglist)
		feeds[feed_name].fetch_filters(cfg)

	conn.close()
	logger.debug(feeds)
	return feeds

def fetch_enabled_feeds(cfg):
	""" return a dictionary of feeds in which key is feed name """

	try:
		conn = sqlite3.connect(cfg.dbfilespec)
	except Exception, e:
		print "Connect fail for db %s: %s" % (cfg.dbfilespec,str(e))
		return None

	c = conn.cursor()

	# get list of feeds and their properties
	query_get_feeds = 'SELECT * FROM feeds WHERE enabled = 1'
	try:
		c.execute(query_get_feeds)
	except Exception, e:
		print "Execute fail on db %s for query %s: %s" \
		 % (cfg.dbfilespec,query_get_feeds,str(e))
		conn.close()
		return None

	# fetchall returns a list of tuples
	rows = []
	try:
		rows = c.fetchall()
	except Exception, e:
		print "Fetchall fail on db %s for query %s: %s" \
		% (cfg.dbfilespec,query_get_feeds,str(e))
		conn.close()
		return None

	feeds = {}
	for r in rows:
		# name is the first element in tuple
		feed_name = r[0]
		arglist = list(r)
		feeds[feed_name] = Feed(*arglist)
		feeds[feed_name].fetch_filters(cfg)

	conn.close()
	logger.debug(feeds)
	return feeds

def fetch_a_feed(cfg,feed_name):
	""" fetch an input feed """

	logger.info("fetching input feed %s" % (feed_name))
	try:
		conn = sqlite3.connect(cfg.dbfilespec)
	except Exception, e:
		msg = "Connect fail for db %s: %s" % (cfg.dbfilespec,str(e))
		logger.error(msg)
		return None

	c = conn.cursor()

	# get list of feeds and their properties
	query_get_feed = "SELECT * FROM feeds WHERE name = '%s'" % (feed_name)
	try:
		c.execute(query_get_feed)
	except Exception, e:
		msg = "Execute fail on db %s for query %s: %s" \
		     % (cfg.dbfilespec,query_get_feed,str(e))
		logger.error(msg)
		conn.close()
		return None

	# fetchone returns a tuple
	row = None
	try:
		row = c.fetchone()
	except Exception, e:
		msg = "Fetchone fail on db %s for query %s: %s" \
		    % (cfg.dbfilespec,query_get_feed,str(e))
		logger.error(msg)
		conn.close()
		return None

	if row == None:
		# no feed found with that name
		conn.close()
		return None
	# should assert that first element in tuple matches feed_name
	column_list = list(row)
	obj = Feed(*column_list)

	conn.close()
	logger.debug(obj)

	# fetch feed's filter(s)
	obj.fetch_filters()
	return obj