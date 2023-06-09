stream {

    log_format tcp '$remote_addr [$time_local] '
                '$protocol $status $bytes_sent '
                '$upstream_addr $upstream_bytes_received '
                '$upstream_bytes_sent $upstream_connect_time';

	access_log /var/log/nginx/relay_access.log tcp;
	error_log /var/log/nginx/relay_error.log;

    upstream node1-key {
        server node1.mydomain.local:60000;
    }

    upstream node2-key {
	server node2.mydomain.local:60000;
    }

    upstream node3-key {
	server node3.mydomain.local:60000;
    }

    upstream node1-msg {
        server node1.mydomain.local:50000;
    }

    upstream node2-msg {
        server node2.mydomain.local:50000;
    }

    upstream node3-msg {
        server node3.mydomain.local:50000;
    }


    server {
        listen 60001;
        proxy_pass node1-key;
    }

    server {
        listen 60002;
        proxy_pass node2-key;
    }

    server {
        listen 60003;
        proxy_pass node3-key;
    }

    server {
        listen 50001;
        proxy_pass node1-msg;
    }

    server {
        listen 50002;
        proxy_pass node2-msg;
    }

    server {
        listen 50003;
        proxy_pass node3-msg;
    }

}