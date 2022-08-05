for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
do
	path="/root/data/server_0715/"
	targetIP="${path}/targets/20x200/${i}_200.ips"
	outputFile="${path}/shanghai/20x200/${i}_output.yrps"

	minttl=6
	maxttl=25
	rate=4000

	sudo ./yarrp -o ${outputFile}  -t ICMP  -r ${rate} -i ${targetIP}  -l ${minttl}  -m ${maxttl}
	sleep 1m
done
