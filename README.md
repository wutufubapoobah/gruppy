Gruppy
======

Provides smart logstash flows optimized for use with S3

Usage
-----

Supposing you have an S3 bucket mounted via fuse at /mnt/mybucket
And it contains a set of log files in this directory: /mnt/mybucket/foobar/<year>/<month>/<date>/

Assume that you've already created a logstash feed config with input codec = 'stdin',
located at /etc/logstash/conf.d/foobar.conf.

You can verify that this feed config works by setting it's output block like this:

.. code-block::json
output {
  stdout {
    codec => rubydebug
  }
}

Run the test like this:

.. code-block::bash

    $ cat foobar1.log | /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/foobar.conf


You should see the parsed results on stdout.

To use gruppy to automate the logstash processing of logs stored on S3,


1. Create a feed

.. code-block::bash
sqlite3 /var/lib/gruppy/gruppy.db "insert into feeds (name,filespec,enabled) values ('foobar','/etc/logstash/conf.d/foobar.conf','1')"


2. Associate an interesting path with the feed

.. code-block::bash
sqlite3 /var/lib/gruppy/gruppy.db "insert into interesting_paths (path,feed_name,pattern) values ('/mnt/mybucket/foobar/$THIS_YEAR/$THIS_MONTH/$THIS_DATE','foobar','*')"


3. Start the gruppy service

.. code-block::bash
systemctl start gruppy.service


