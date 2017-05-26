from setuptools import setup

setup(  name='gruppy',
	version='0.1.0',
	description='Provides smart logstash flows optimized for use with S3',
	url='https://github.com/wutufubapoobah/gruppy',
	author='WutuFuBaPooBah',
	author_email='wutufubapoobah@gmail.com',
	license='GPL',
	packages=['gruppy'],
        package_dir={'gruppy': 'gruppy'},
        data_files=[
			('/etc/gruppy',['etc/gruppy.yml']),
			('/etc/systemd/system',['sys/gruppy.service']),
			('/var/lib/gruppy',['data/gruppy.db']),
			('/var/log/gruppy',['sys/gruppy.log'])
	],
	install_requires=[
		'sqlite3',
		'shutil',
		'argparse',
		'logging',
		'datetime',
		'fnmatch',
		'shlex',
		'warnings'
	],
	# scripts get installed into PATH, presumably /usr/bin
	scripts=[ 'bin/gruppy', 'bin/gruppyd', 'bin/gruppy-run-once'],
        keywords='ELK, logstash, S3',
	classifiers=[
		'Environment :: Console',
		'Intended Audience :: System Administrators',
		'License :: GPL',
		'Operating System :: Linux',
		'Operating System :: CentOS'
	],
	log_description='See the README and contents of docs directory for full description',
	zip_safe=False)
