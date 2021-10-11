#!/usr/bin/env bash

function usage() {
    cat << EOF
usage: $0

    -h|--help               Print this help message.
    -p|--program=<string>   The program against which to test the attack
    -i|--iterations=<int>   How many times to perform the attack
EOF
}

getopt --test >/dev/null
if [[ $? -ne 4 ]]; then
    echo "Requires newer getopt. Exiting..."
    exit 1
fi

OPTS=hi:p:
LONGOPTS=help,iterations,program
PARSED=$(getopt --options=$OPTS --longoptions=$LONGOPTS --name "$0" -- "$@")
if [[ $? -ne 0 ]]; then
    exit 1
fi
eval set -- "$PARSED"

num_experiments=
program=
program_path="src/"
while true; do
    case "$1" in
    -h|--help)
    usage
    exit 0
    ;;
    -i|--iterations)
    if [ -n "$2" ] &&  [ "$2" -eq "$2" ] 2>/dev/null; then
        num_experiments="$2"
    else
        echo "Number of iterations must be an integer"
        exit 1
    fi
    if [ "$num_experiments" -lt 0 ]; then
        echo "Number of iterations must be a positive integer"
        exit 1
    fi
    shift 2
    ;;
    -p|--program)
    program_path="$program_path$2"
    if [ ! -f "$program_path" ]; then
        echo "Program $program_path does not exist"
        exit 1
    fi
    program="$2"
    shift 2
    ;;
    --)
    shift
    break
    ;;
    *)
    echo "Unknown options"
    exit 1
    ;;
    esac
done

if [ -z "$program" ]; then
    echo "Missing the program"
    exit 1
fi
if [ -z "$num_experiments" ]; then
    echo "Missing the number of iterations"
    exit 1
fi

function itoa
{
    echo -n $(($(($(($((${1}/256))/256))/256))%256)).
    echo -n $(($(($((${1}/256))/256))%256)).
    echo -n $(($((${1}/256))%256)).
    echo $((${1}%256))
}

program_log="/tmp/$program.log"
rm -rf "$program_log"

# Run the tracing program in background (discarding stdout and storing stderr)
nohup "$program_path" >/dev/null 2>"$program_log" &
pid=$!

function cleanup {
    kill -9 $pid
}
trap cleanup EXIT

# Block in case it is not running
if ! ps -p $pid &>/dev/null; then
    echo "$program not running"
    exit 1
fi

echo "$program: PID: [$pid]"

sleep .5

attack_log="/tmp/${program}_attack.log"
rm -rf "$attack_log"
# Run the attacks
for (( c=1; c<=num_experiments; c++ ))
do
   res=$(exec "phantom-attack/phantom_v1/attack_connect" | tail -1)
   echo "attack_connect: $res: $(itoa "$res")" | tee -a "$attack_log"
done

# Statistics time
program_worked=0
program_failed=0
while IFS= read -r attack_line && IFS= read -r report_line <&3; do
   attack_integer=$(echo "$attack_line" | cut -d':' -f2 | sed -e 's/^[[:space:]]*//')
   attack_address=$(echo "$attack_line" | cut -d':' -f3 | sed -e 's/^[[:space:]]*//')
   report_address=$(echo "$report_line" | cut -d':' -f4 | sed -e 's/^[[:space:]]*//') # can also be an integer
   if [[ "$report_address" == "$attack_address" ]] || [[ "$report_address" == "$attack_integer" ]]; then
     program_worked=$((program_worked+1))
   else
     program_failed=$((program_failed+1))
   fi
done < "$attack_log" 3< "$program_log"

echo "The program $program correctly reported the value $program_worked out of $num_experiments times"

# Another way of computing statistics could be:
# attack_address == "1.1.1.1" && report_address != "1.1.1.1" => tracing_failure += 1
# attack_address == "1.1.1.1" && report_address == "1.1.1.1" => tracing_success += 1
# attack_address != "1.1.1.1" && report_address == attack_address => tracing_success += 1
# attack_address != "1.1.1.1" && report_address != attack_address => tracing_failues += 1

exit 0