path="/root/data/server_0901"
targetIP="${path}/abnor_ips/abnor_dst"
outputFile="${path}/rtt/shanghai_02/abnor_dst.yrps"

minttl=6
maxttl=25
rate=180

sudo ./yarrp -o ${outputFile}  -t UDP -r ${rate} -i ${targetIP}  -l ${minttl}  -m ${maxttl} -C
