#!/usr/bin/env bash

DBG_TEST=3
DBG_APP=3
NBR_CLIENTS=3
NBR_SERVERS=3
NBR_SERVERS_GROUP=$NBR_SERVERS
. $GOPATH/src/gopkg.in/dedis/onet.v1/app/libtest.sh

MERGE_FILE=""
main(){
	startTest
	buildConode gopkg.in/dedis/cothority.v1/cosi/service github.com/dedis/student_17_pop/service
	echo "Creating directories"
	for n in $(seq $NBR_CLIENTS); do
		cl=cl$n
		rm -f $cl/*
		mkdir -p $cl
	done
	addr=()
	addr[1]=127.0.0.1:2002
	addr[2]=127.0.0.1:2004
	addr[3]=127.0.0.1:2006

	#test Build
	#test Check
	#test OrgLink
	#test Save
	#test OrgConfig
	#test AtCreate
	#test OrgPublic
	#test OrgPublic2
	#test OrgFinal1
	#test OrgFinal2
	#test OrgFinal3
	#test AtJoin
	#test AtSign
	#test AtVerify
	#test AtMultipleKey
	test Merge
	stopTest
}

testMerge(){
	MERGE_FILE="pop_merge.toml"
	mkFinal

	# TODO: Should be OK not?
	# I suppose NO.
	#testOK runCl 1 attendee join ${priv[1]} ${pop_hash[1]}
	#testOK runCl 2 attendee join ${priv[2]} ${pop_hash[2]}
	#testOK runCl 3 attendee join ${priv[3]} ${pop_hash[3]}
	
	testFail runCl 1 org merge
	testFail runCl 2 org merge ${pop_hash[1]}

	testOK runCl 1 org merge ${pop_hash[1]}

	testOK runCl 1 attendee join ${priv[1]} ${pop_hash[1]}
	testOK runCl 2 attendee join ${priv[2]} ${pop_hash[2]}
	testOK runCl 3 attendee join ${priv[3]} ${pop_hash[3]}

	for i in {1..3}; do
		runDbgCl 1 $i attendee sign msg1 ctx1 ${pop_hash[$i]} | tee sign$i.toml
		tag[$i]=$( grep Tag: sign$i.toml | sed -e "s/.* //")
		sig[$i]=$( grep Signature: sign$i.toml | sed -e "s/.* //")
	done

	testOK runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[1]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[1]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[1]}

	testOK runCl 2 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
	testOK runCl 2 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[2]}
	testOK runCl 2 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[2]}

	testOK runCl 3 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[3]}
	testOK runCl 3 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[3]}
	testOK runCl 3 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[3]}

}


testAtMultipleKey(){
	mkConfig 2 2 2 3
	# att1.k1 - p1 att1.k2 - p2 att2 - p2
	runCl 1 org public ${pub[1]} ${pop_hash[1]}
	runCl 2 org public ${pub[1]} ${pop_hash[1]}

	runCl 1 org public ${pub[2]} ${pop_hash[2]}
	runCl 2 org public ${pub[2]} ${pop_hash[2]}

	runCl 1 org public ${pub[3]} ${pop_hash[2]}
	runCl 2 org public ${pub[3]} ${pop_hash[2]}

	runCl 1 org final  ${pop_hash[1]}
	runCl 2 org final  ${pop_hash[1]}
	runCl 1 org final  ${pop_hash[2]}
	runCl 2 org final  ${pop_hash[2]}


	testOK runCl 1 attendee join ${priv[1]} ${pop_hash[1]}
	testOK runCl 1 attendee join ${priv[2]} ${pop_hash[2]}
	testOK runCl 2 attendee join ${priv[3]} ${pop_hash[2]}

	runDbgCl 1 1 attendee sign msg1 ctx1 ${pop_hash[1]} > sign.toml
	tag[1]=$( grep Tag: sign.toml | sed -e "s/.* //")
	sig[1]=$( grep Signature: sign.toml | sed -e "s/.* //")


	runDbgCl 1 1 attendee sign msg1 ctx1 ${pop_hash[2]} > sign.toml
	tag[2]=$( grep Tag: sign.toml | sed -e "s/.* //")
	sig[2]=$( grep Signature: sign.toml | sed -e "s/.* //")


	runDbgCl 1 2 attendee sign msg1 ctx1 ${pop_hash[2]} > sign.toml
	tag[3]=$( grep Tag: sign.toml | sed -e "s/.* //")
	sig[3]=$( grep Signature: sign.toml | sed -e "s/.* //")

	testOK runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[1]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
	testOK runCl 2 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[2]}

	testFail runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[1]}
	testFail runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[2]}
	testFail runCl 2 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[1]}
	testFail runCl 2 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[1]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[2]}
	testOK runCl 2 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
}

testAtVerify(){
	mkClSign
	testFail runCl 1 attendee verify msg1 ctx1 ${tag[1]} ${sig[1]}
	testFail runCl 1 attendee verify msg1 ctx1 ${tag[1]} ${sig[1]} ${pop_hash[1]}
	testFail runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[2]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[1]} ${pop_hash[1]}
	testFail runCl 1 attendee verify msg1 ctx1 ${sig[1]} ${tag[2]} ${pop_hash[1]}

	testFail runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[1]}
	testOK runCl 2 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
	testFail runCl 2 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[2]}
	testOK runCl 3 attendee verify msg1 ctx1 ${sig[3]} ${tag[3]} ${pop_hash[3]}

	testFail runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
	testOK runCl 1 attendee join ${priv[1]} ${pop_hash[2]}
	testOK runCl 1 attendee verify msg1 ctx1 ${sig[2]} ${tag[2]} ${pop_hash[2]}
}

tag=()
sig=()
mkClSign(){
	mkAtJoin
	for i in {1..3}; do
		runDbgCl 1 $i attendee sign msg1 ctx1 ${pop_hash[$i]} > sign$i.toml
		tag[$i]=$( grep Tag: sign$i.toml | sed -e "s/.* //")
		sig[$i]=$( grep Signature: sign$i.toml | sed -e "s/.* //")
	done
}

testAtSign(){
	mkFinal
	testFail runCl 1 attendee sign msg1 ctx1 ${pop_hash[1]}
	for i in {1..3}; do
		runCl $i attendee join ${priv[$i]} ${pop_hash[$i]}
	done
	testFail runCl 1 attendee sign
	testFail runCl 1 attendee sign msg1 ctx1 ${pop_hash[2]}
	testOK runCl 1 attendee sign msg1 ctx1 ${pop_hash[1]}
	testOK runCl 2 attendee sign msg2 ctx2 ${pop_hash[2]}
	testOK runCl 3 attendee sign msg3 ctx3 ${pop_hash[3]}
}

mkAtJoin(){
	mkFinal
	for i in {1..3}; do
		runCl $i attendee join ${priv[$i]} ${pop_hash[$i]}
	done
}

testAtJoin(){
	mkConfig 3 3 2 3

	# att1 - p1, p2; att2 - p2; att3 - p3;
	runCl 1 org public ${pub[1]} ${pop_hash[1]}
	runCl 3 org public ${pub[1]} ${pop_hash[1]}
	runCl 1 org public ${pub[2]} ${pop_hash[2]}
	runCl 2 org public ${pub[2]} ${pop_hash[2]}
	runCl 2 org public ${pub[3]} ${pop_hash[3]}
	runCl 3 org public ${pub[3]} ${pop_hash[3]}

	runCl 1 org public ${pub[1]} ${pop_hash[2]}
	runCl 2 org public ${pub[1]} ${pop_hash[2]}

	# check that fails without finalization
	testFail runCl 1 attendee join ${priv[1]} ${pop_hash[1]}

	runCl 1 org final  ${pop_hash[1]}
	runCl 3 org final  ${pop_hash[1]}
	runCl 1 org final  ${pop_hash[2]}
	runCl 2 org final  ${pop_hash[2]}
	runCl 2 org final  ${pop_hash[3]}
	runCl 3 org final  ${pop_hash[3]}

	testFail runCl 1 attendee join
	testFail runCl 1 attendee join ${priv[1]}
	testFail runCl 1 attendee join badkey ${pop_hash[1]}
	testFail runCl 1 attendee join ${priv[1]} ${pop_hash[3]}
	testOK runCl 1 attendee join ${priv[1]} ${pop_hash[1]}
	testOK runCl 2 attendee join ${priv[2]} ${pop_hash[2]}
	testOK runCl 3 attendee join ${priv[3]} ${pop_hash[3]}
}

mkFinal(){
	mkConfig 3 3 2 3

	# att1 - p1, p2; att2 - p2; att3 - p3;
	runCl 1 org public ${pub[1]} ${pop_hash[1]}
	runCl 3 org public ${pub[1]} ${pop_hash[1]}
	runCl 1 org public ${pub[2]} ${pop_hash[2]}
	runCl 2 org public ${pub[2]} ${pop_hash[2]}
	runCl 2 org public ${pub[3]} ${pop_hash[3]}
	runCl 3 org public ${pub[3]} ${pop_hash[3]}

	runCl 1 org public ${pub[1]} ${pop_hash[2]}
	runCl 2 org public ${pub[1]} ${pop_hash[2]}

	runCl 1 org final  ${pop_hash[1]}
	runCl 3 org final  ${pop_hash[1]}
	runCl 1 org final  ${pop_hash[2]}
	runCl 2 org final  ${pop_hash[2]}
	runCl 2 org final  ${pop_hash[3]}
	runCl 3 org final  ${pop_hash[3]}
}

testOrgFinal3(){
	mkConfig 3 3 2 1
	runCl 1 org public ${pub[1]} ${pop_hash[1]}
	runCl 1 org public ${pub[1]} ${pop_hash[2]}
	runCl 2 org public ${pub[1]} ${pop_hash[2]}
	runCl 2 org public ${pub[1]} ${pop_hash[3]}
	runCl 3 org public ${pub[1]} ${pop_hash[1]}
	runCl 3 org public ${pub[1]} ${pop_hash[3]}

	testFail runCl 1 org final ${pop_hash[1]}
	testFail runCl 2 org final ${pop_hash[1]}
	testOK runCl 3 org final ${pop_hash[1]}

	testFail runCl 1 org final ${pop_hash[2]}
	testFail runCl 3 org final ${pop_hash[2]}
	testOK runCl 2 org final ${pop_hash[2]}

	testFail runCl 2 org final ${pop_hash[3]}
	testOK runCl 3 org final ${pop_hash[3]}
}


testOrgFinal2(){
	mkConfig 2 1 1 2
	runCl 1 org public ${pub[2]} ${pop_hash[1]}
	runCl 2 org public ${pub[1]} ${pop_hash[1]}
	runCl 2 org public ${pub[2]} ${pop_hash[1]}
	testFail runCl 1 org final ${pop_hash[1]}
	testOK runCl 2 org final ${pop_hash[1]}
	testOK runCl 1 org final ${pop_hash[1]}
	runDbgCl 1 1 org final ${pop_hash[1]} > final1.toml
	runDbgCl 1 2 org final ${pop_hash[1]} > final2.toml
	testNGrep , echo $( runCl 1 org final | grep Attend )
	testNGrep , echo $( runCl 2 org final | grep Attend )
	cmp -s final1.toml final2.toml
	testOK [ $? -eq 0 ]
}

testOrgFinal1(){
	mkConfig 2 1 1 2
	runCl 1 org public ${pub[1]} ${pop_hash[1]}
	runCl 1 org public ${pub[2]} ${pop_hash[1]}
	runCl 2 org public "\[\"${pub[1]}\",\"${pub[2]}\"\]" ${pop_hash[1]}
	testFail runCl 1 org final
	testFail runCl 1 org final bad_hash
	testFail runCl 1 org final ${pop_hash[1]}
	testOK runCl 2 org final ${pop_hash[1]}
}

testOrgPublic2(){
	mkConfig 3 3 2 1
	testOK runCl 1 org public ${pub[1]} ${pop_hash[1]}
	testOK runCl 1 org public ${pub[1]} ${pop_hash[2]}
	testOK runCl 2 org public ${pub[1]} ${pop_hash[2]}
	testOK runCl 2 org public ${pub[1]} ${pop_hash[3]}
	testOK runCl 3 org public ${pub[1]} ${pop_hash[1]}
	testOK runCl 3 org public ${pub[1]} ${pop_hash[3]}

	testFail runCl 3 org public ${pub[1]} ${pop_hash[2]}
}

testOrgPublic(){
	mkConfig 1 1 1 2
	testFail runCl 1 org public
	testFail runCl 1 org public ${pub[1]}
	testFail runCl 1 org public ${pub[1]} wrong_hash
	testOK runCl 1 org public ${pub[1]} ${pop_hash[1]}
	testFail runCl 1 org public ${pub[1]} ${pop_hash[1]}
	testOK runCl 1 org public ${pub[2]} ${pop_hash[1]}
}

# need to store many party hashes as variables
pop_hash=()
# usage: $1 organizer and $2 parties, each has $3 parties, $4 key pairs
# example: 3 organizers, 2 parties for each
# 1st org: parties #1, #2
# 2nd org: parties #2, #3
# 3rd org: parties #1, #3
mkConfig(){
	local cl
	local pc
	mkLink $1
	mkPopConfig $2 $1
	mkKeypair $4
	for (( cl=1; cl<=$1; cl++ ))
	do
		for (( pc=1; pc<=$3; pc++ ))
		do
			num_pc=$((($pc + $cl + 1) % $2 + 1))
			#runDbgCl 1 $cl org config pop_desc$num_pc.toml group$num_pc.toml > pop_hash
			runDbgCl 1 $cl org config pop_desc$num_pc.toml $MERGE_FILE | tee pop_hash_file
			pop_hash[$num_pc]=$(grep config: pop_hash_file | sed -e "s/.* //")
		done
	done
}

testAtCreate(){
	testOK runCl 1 attendee create
	runDbgCl 1 1 attendee create > keypair.1
	runDbgCl 1 1 attendee create > keypair.2
	cmp keypair.1 keypair.2
	testOK [ $? -eq 1 ]
}

priv=()
pub=()
mkKeypair(){
	local i
	for (( i=1; i<=$1; i++ ))
	do
		runDbgCl 1 1 attendee create > keypair
		priv[i]=$( grep Private keypair | sed -e "s/.* //" )
		pub[i]=$( grep Public keypair | sed -e "s/.* //" )
	done
}

testOrgConfig(){
	mkPopConfig 1 1
	testFail runCl 1 org config pop_desc1.toml
	mkLink 2
	testOK runCl 1 org config pop_desc1.toml
	testOK runCl 2 org config pop_desc1.toml
}

# $1 number of parties $2 number of organizers
mkPopConfig(){
	local n
	for (( n=1; n<=$1; n++ ))
	do
		cat << EOF > pop_desc$n.toml
Name = "Proof-of-Personhood Party"
DateTime = "2017-08-08 15:00 UTC"
Location = "Earth, City$n"
EOF
	done
	for (( n=1; n<=$2; n++ ))
	do
		sed -n "$((4*$n-3)),$((4*$n))p" public.toml >> pop_desc$n.toml
		if [[ $2 -gt 1 ]]
		then
			local m=$(($n%$2 + 1))
			sed -n "$((4*$n-3)),$((4*$n))p" public.toml >> pop_desc$m.toml
		fi
	done
	
	for (( n=1; n<=$1; n++ ))
	do
		cat << EOF >> pop_merge.toml
[[parties]]
Location = "Earth, City$n"
EOF
		echo "[[parties.servers]]" >> pop_merge.toml
		sed -n "$((4*$n-2)),$((4*$n))p" public.toml >> pop_merge.toml
		local m=$(($n%$NBR_SERVERS + 1))
		echo "[[parties.servers]]" >> pop_merge.toml
		sed -n "$((4*$m-2)),$((4*$m))p" public.toml >> pop_merge.toml
	done
	cat pop_merge.toml
}

# $1 number of parties $2 number of organizers
#mkPopConfig(){
#	local n
#	for (( n=1; n<=$1; n++ ))
#	do
#		cat << EOF > pop_desc$n.toml
#Name = "33c3 Proof-of-Personhood Party"
#DateTime = "2016-12-29 15:00 UTC"
#Location = "Earth, Germany, City$1, Hall A1"
#EOF
#	done
#	for (( n=1; n<=$1; n++ ))
#	do
#		sed -n "$((4*$n-3)),$((4*$n))p" public.toml >> pop_desc$(($n%$1+1)).toml
#		if [[ $2 -gt 1 ]]
#		then
#			local m=$(($n%$2 + 1))
#			sed -n "$((4*$m-3)),$((4*$m))p" public.toml >> pop_desc$(($n%$1+1)).toml
#		fi
#	done
#}

testSave(){
	runCoBG 1 2
	mkPopConfig 1 2

	testFail runCl 1 org config pop_desc1.toml
	pkill -9 -f conode
	mkLink 2
	pkill -9 -f conode
	runCoBG 1 2
	testOK runCl 1 org config pop_desc1.toml
}

mkLink(){
	runCoBG `seq $1`
	for (( serv=1; serv<=$1; serv++ ))
	do
		runCl $serv org link ${addr[$serv]}
		pin=$( grep PIN ${COLOG}$serv.log | sed -e "s/.* //" )
		testOK runCl $serv org link ${addr[$serv]} $pin
	done
}

testOrgLink(){
	runCoBG 1 2
	testOK runCl 1 org link ${addr[1]}
	testGrep PIN cat ${COLOG}1.log
	pin1=$( grep PIN ${COLOG}1.log | sed -e "s/.* //" )
	testFail runCl 1 org link ${addr[1]} abcdefg
	testOK runCl 1 org link ${addr[1]} $pin1
	testOK runCl 2 org link ${addr[2]}
	testGrep PIN cat ${COLOG}2.log
	pin2=$( grep PIN ${COLOG}2.log | sed -e "s/.* //" )
	testOK runCl 2 org link ${addr[2]} $pin2
}

testCheck(){
	runCoBG 1 2 3
	cat co*/public.toml > check.toml
	testOK dbgRun ./$APP -d $DBG_APP check check.toml
}

testBuild(){
	testOK dbgRun ./conode --help
	testOK dbgRun ./$APP --help
}

runCl(){
	local CFG=cl$1
	shift
	dbgRun ./$APP -d $DBG_APP -c $CFG $@
}

runDbgCl(){
	local DBG=$1
	local CFG=cl$2
	shift 2
	./$APP -d $DBG -c $CFG $@
}

main
