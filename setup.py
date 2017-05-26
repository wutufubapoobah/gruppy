from setuptools import setup

setup(  name='gruppy',
	version='0.1.1',
	description='Provides smart logstash flows optimized for use with S3',
	url='https://github.com/wutufubapoobah/gruppy',
	author='WutuFuBaPooBah',
	author_email='wutufubapoobah@gmail.com',
	license='MIT',
        platforms=['CentOS7'],
	packages=['gruppy'],
        package_dir={'gruppy': 'gruppy'},
        data_files=[
			('/etc/gruppy',['etc/gruppy.yml']),
			('/etc/systemd/system',['sys/gruppy.service']),
			('/var/lib/gruppy',['data/gruppy.db']),
			('/var/log/gruppy',['sys/gruppy.log'])
	],
	scripts=[ 'bin/gruppy', 'bin/gruppyd', 'bin/gruppy-run-once'],
        keywords='ELK, logstash, S3',
	classifiers=[
		'Environment :: Console',
		'Intended Audience :: System Administrators',
		'License :: OSI Approved :: MIT License',
		'Operating System :: POSIX :: Linux'
	],
	long_description='See the README and contents of docs directory for full description',
	zip_safe=True)
