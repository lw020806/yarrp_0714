path="/home/qiling/Documents/server_0901"
targetIP="${path}/abnor_ips/abnor_hops"
outputFile="${path}/rtt/um_01/abnor_hops.yrps"

minttl=25
maxttl=25
rate=18

sudo ./yarrp -o ${outputFile}  -t UDP -r ${rate} -i ${targetIP}  -l ${minttl}  -m ${maxttl} -C
