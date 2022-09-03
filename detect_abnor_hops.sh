for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
do
	path="/root/data/server_0901"
	targetIP="${path}/targets/20x200/${i}_200.ips"
	outputFile="${path}/rtt/shanghai/20x200/${i}_output.yrps"

	minttl=6
	maxttl=25
	rate=4000

	sudo ./yarrp -o ${outputFile}  -t UDP -r ${rate} -i ${targetIP}  -l ${minttl}  -m ${maxttl} -C
	sleep 1m
done
