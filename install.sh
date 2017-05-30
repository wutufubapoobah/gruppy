#!/bin/sh

if [[ ! $1 == 'y' && ! $1 == '-y' ]];then

	cat <<EOF

  This installs gruppy. It will:

 1. create /etc/gruppy
 2. copy etc/gruppy.yml to /etc/gruppy
 3. create /var/lib/gruppy
 4. copy data/gruppy.db to /var/lib/gruppy
 5. create /var/log/gruppy
 6. copy gruppy.service to /lib/systemd/system/

EOF
	read -p "Continue? [Y/n] " response
	if [[ "$response" == "n" || "$response" == "N" ]];then
		echo "Cancelled at user request"
		exit 1;
	fi
fi


mkdir /etc/gruppy
cp etc/gruppy.yml /etc/gruppy

mkdir /var/lib/gruppy
cp data/gruppy.db /var/lib/gruppy

mkdir /var/log/gruppy
cp sys/gruppy.service /lib/systemd/system/
