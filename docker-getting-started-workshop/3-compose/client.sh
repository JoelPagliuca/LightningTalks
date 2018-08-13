while [ 1 ]
do
	echo "Sending message to server"
	echo "Message from client" | nc -q1 server 8080
	sleep 1
done